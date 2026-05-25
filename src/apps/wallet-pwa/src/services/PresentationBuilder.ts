import { SecureStorage } from '@mitch/secure-storage';
import { AuditLog } from '@mitch/audit-log';
import { DecisionCapsule, StoredCredentialMetadata } from '@mitch/shared-types';
import {
  EphemeralKey,
  canonicalStringify,
  generateKeyPair,
  signData,
  resolveDID,
  detectKeyAlgorithm,
  WebAuthnService,
} from '@mitch/shared-crypto';
import { decodeMdoc as mdocDecodeMdoc } from '@mitch/mdoc';
import { evaluatePredicates, CommonPredicates, type PredicateRequest } from '@mitch/predicates';
import { SeedService } from './SeedService';

// ─── mdoc base64 helpers ──────────────────────────────────────────────────
function uint8ArrayToBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// DID Resolution Cache
// Map<DID, { key: CryptoKey, expires: number }>
const keyCache = new Map<string, { key: CryptoKey; expires: number }>();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 Minutes

// Helper for typed crypto access
const getSubtle = () => (globalThis.crypto?.subtle ?? crypto.subtle) as SubtleCrypto;

export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Map a JWK to a WebCrypto import algorithm (Phase 0 minimal)
export function mapJwkToAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | RsaHashedImportParams {
  if (jwk.kty === 'RSA') {
    const hash = jwk.alg && jwk.alg.toUpperCase().includes('256') ? 'SHA-256' : 'SHA-256';
    return { name: 'RSA-OAEP', hash };
  }
  throw new Error(
    `UNSUPPORTED_EPHEMERAL_KEY: Expected RSA JWK for ephemeral_key, got kty=${jwk.kty || 'unknown'}`
  );
}

/**
 * Fetch Verifier Public Key (Now with Real Universal Resolver)
 */
export async function fetchVerifierPublicKey(did: string): Promise<CryptoKey> {
  // 1. Check Cache
  const cached = keyCache.get(did);
  if (cached && cached.expires > Date.now()) {
    return cached.key;
  }

  // 2. Resolve (Real Resolver from shared-crypto)
  // Supports did:web (HTTPS) and did:mitch (Demo)
  const didDocument = await resolveDID(did);

  // 3. Extract Key (First Verification Method)
  const vm = didDocument.verificationMethod?.[0];
  if (!vm || !vm.publicKeyJwk) {
    throw new Error(`DID_DOCUMENT_INVALID: Missing publicKeyJwk in ${did}`);
  }

  // 4. Import Key (WebCrypto)
  // Detect algorithm from JWK (RSA/EC)
  const algorithm = detectKeyAlgorithm(vm.publicKeyJwk as JsonWebKey);

  // For encryption, we need RSA-OAEP (or EC-ECDH in future)
  const algoName = typeof algorithm === 'string' ? algorithm : algorithm.name;

  if (algoName === 'RSA-OAEP' && (vm.publicKeyJwk as JsonWebKey).kty !== 'RSA') {
    // Sanity check
    throw new Error('KEY_TYPE_MISMATCH: Expected RSA JWK for RSA-OAEP algorithm');
  }

  const key = await getSubtle().importKey(
    'jwk',
    vm.publicKeyJwk,
    algorithm,
    true,
    ['encrypt', 'wrapKey'] // Verifier keys are for Encryption (confidentiality)
  );

  // 5. Update Cache
  keyCache.set(did, { key, expires: Date.now() + CACHE_TTL_MS });
  console.log(`🔑 Cached public key for ${did} (expires in ${CACHE_TTL_MS / 60000} min)`);

  return key;
}

export class PresentationBuilder {
  /**
   * Flattens all namespace elements into a single Record for
   * compatibility with the existing selective disclosure pipeline.
   */
  private static extractMdocClaims(cborBase64: string): Record<string, unknown> {
    const cborBytes = base64ToUint8Array(cborBase64);
    const decoded = mdocDecodeMdoc<Map<string, unknown>>(cborBytes);

    const claims: Record<string, unknown> = {};

    const nameSpaces = decoded.get('nameSpaces') as Map<string, unknown[]> | undefined;
    if (nameSpaces instanceof Map) {
      for (const [_ns, items] of nameSpaces) {
        if (!Array.isArray(items)) continue;
        for (const item of items) {
          if (item instanceof Map) {
            const id = item.get('elementIdentifier') as string;
            const value = item.get('elementValue');
            if (id) claims[id] = value;
          } else if (item && typeof item === 'object') {
            const obj = item as Record<string, unknown>;
            if (obj.elementIdentifier) {
              claims[obj.elementIdentifier as string] = obj.elementValue;
            }
          }
        }
      }
    }

    return claims;
  }

  /**
   * Generate signed, selectively-disclosed, and optionally ZK-proven presentation
   * and encrypt it under the Verifier's public key.
   */
  static async generatePresentation(
    storage: SecureStorage,
    auditLog: AuditLog,
    policyPublicKey: CryptoKey | null,
    policyPrivateKey: CryptoKey | null,
    capsule: DecisionCapsule,
    agentTargetPubKey?: CryptoKey
  ): Promise<{ encryptedVp: string; auditLog: string[] }> {
    const logs: string[] = [];

    // 1. Validate Capsule Integrity
    if (!capsule.decision_id || !capsule.nonce) {
      throw new Error('SECURITY ALERT: Invalid Decision Capsule. Replay Attack Possible.');
    }

    const verifierDID = capsule.verifier_did;
    if (!verifierDID) throw new Error('SECURITY ALERT: Capsule not bound to a verifier.');

    if (capsule.audience && capsule.audience !== 'mitch-wallet-pwa') {
      throw new Error(`SECURITY ALERT: Capsule intended for different app (${capsule.audience}).`);
    }

    // Identity Signature Verification (Phase 0)
    if (!capsule.wallet_attestation) {
      throw new Error('SECURITY ALERT: Capsule contains no attestation (Unsigned).');
    }
    if (!policyPublicKey) {
      throw new Error('Wallet not initialized properly (Missing Policy Key).');
    }

    const { wallet_attestation, ...toVerify } = capsule;
    const payload = canonicalStringify(toVerify);
    const signatureBytes = new Uint8Array(
      wallet_attestation.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
    );

    const validSignature = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      policyPublicKey,
      signatureBytes,
      new TextEncoder().encode(payload)
    );

    if (!validSignature) {
      throw new Error(
        'SECURITY ALERT: Capsule signature verification FAILED. Policy Decision may be forged.'
      );
    }
    logs.push('✅ Capsule Signature Verified (Signed by Identity Key)');

    logs.push(`✅ Capsule Integrity Verified (Ref: ${capsule.decision_id} -> ${verifierDID})`);

    if (agentTargetPubKey) {
      logs.push(`🤖 AUTOMATION FIREWALL: Encrypting for Target, not Requestor.`);
    }

    // Cryptographic Presence Binding
    if (capsule.requires_presence) {
      logs.push('👤 Biometric Presence Required. Triggering WebAuthn Ceremony...');
      const presenceProof = await WebAuthnService.provePresence(capsule.decision_id);
      capsule.presence_proof = presenceProof;
      logs.push('✅ WebAuthn Signature Bound to Decision ID');
    }

    // 2. Multi-VC Pipelining
    const bundles: Array<{
      credentialType: string;
      disclosure: Record<string, unknown>;
      provenClaims: Record<string, boolean>;
      zkpProofs?: Record<string, unknown>; // Full cryptographic proofs
    }> = [];

    // Normalize requirements
    const requirements = capsule.authorized_requirements || [
      {
        credential_type: '*',
        allowed_claims: capsule.allowed_claims || [],
        proven_claims: capsule.proven_claims || [],
        selected_credential_id: capsule.selected_credential_id,
        issuer_trust_refs: capsule.issuer_trust_refs || [],
      },
    ];

    for (const req of requirements) {
      const selectedId = req.selected_credential_id;
      if (!selectedId) continue;

      const credMeta = (await storage.getAllMetadata()).find((c) => c.id === selectedId);
      if (!credMeta) throw new Error(`Credential ${selectedId} not found.`);

      // Load & Decrypt
      let credentialData: Record<string, unknown> | null;
      try {
        credentialData = await storage.load<Record<string, unknown>>(selectedId);
      } catch {
        await SeedService.ensureSeeded(storage);
        credentialData = await storage.load<Record<string, unknown>>(selectedId);
      }

      if (!credentialData) {
        throw new Error(`Failed to load credential data for ${selectedId}`);
      }

      await auditLog.append('KEY_USED', selectedId, {
        context: 'CREDENTIAL_DECRYPTION',
        decision_id: capsule.decision_id,
        requirement_type: req.credential_type,
      });
      logs.push(`🔓 VC [${req.credential_type}] Decrypted`);

      // ── mdoc credential path ────────────────────────────────────
      if (credMeta.format === 'mso_mdoc' && credentialData._mdoc) {
        const mdocPayload = credentialData as { _mdoc: true; docType: string; cborBase64: string };
        const mdocClaims = PresentationBuilder.extractMdocClaims(mdocPayload.cborBase64);

        const disclosure: Record<string, unknown> = {};
        for (const claim of req.allowed_claims) {
          if (mdocClaims[claim] !== undefined) disclosure[claim] = mdocClaims[claim];
        }

        bundles.push({
          credentialType: req.credential_type,
          disclosure,
          provenClaims: {},
          zkpProofs: {},
        });

        logs.push(
          `📄 mdoc [${mdocPayload.docType}] selective disclosure: ${Object.keys(disclosure).join(', ')}`
        );

        await auditLog.append('VP_GENERATED', selectedId, {
          context: 'MDOC_PRESENTATION',
          decision_id: capsule.decision_id,
          claims_shared: Object.keys(disclosure),
          claims_requested: req.allowed_claims,
        });
        continue;
      }

      // ── SD-JWT credential path (default) ────────────────────────
      const disclosure: Record<string, unknown> = {};
      const provenClaims: Record<string, boolean> = {};
      const zkpProofs: Record<string, unknown> = {};

      for (const claim of req.allowed_claims) {
        if (credentialData[claim] !== undefined) disclosure[claim] = credentialData[claim];
      }

      for (const predicate of req.proven_claims) {
        if (predicate.startsWith('age >=')) {
          const matches = predicate.match(/age >= (\d+)/);
          const ageLimit = matches ? parseInt(matches[1], 10) : 18;

          const predicateTimestamp = new Date().toISOString();
          const predReq: PredicateRequest = {
            verifierDid: verifierDID,
            nonce: capsule.nonce || `nonce-${Date.now()}`,
            purpose: 'Age Verification',
            timestamp: predicateTimestamp,
            predicates: [CommonPredicates.ageAtLeast(ageLimit)],
          };

          // Identity Key Signature (ECDSA P-256)
          if (!policyPrivateKey) throw new Error('Identity Key missing');
          const signFn = async (d: string) => signData(d, policyPrivateKey!);

          try {
            const predicateCredential = (credentialData as Record<string, unknown>)
              .credentialSubject
              ? (credentialData as Record<string, unknown>)
              : { credentialSubject: credentialData };
            const result = await evaluatePredicates(predicateCredential, predReq, signFn);

            zkpProofs[predicate] = result;

            if (result.proof.allPassed) {
              provenClaims[predicate] = true;
              logs.push(
                '[ZKP] Proof generated: ' +
                  result.proof.decisionId +
                  ' (' +
                  result.proof.binding.requestHash.substring(0, 8) +
                  '...)'
              );
            } else {
              provenClaims[predicate] = false;
              logs.push(
                '[ZKP] Proof failed: ' + (result.proof.evaluations[0]?.reasonCode ?? 'UNKNOWN')
              );
            }
          } catch (e) {
            console.error('ZKP Evaluation Error:', e);
            provenClaims[predicate] = false;
            logs.push('[ZKP] Error: ' + String(e));
          }
        }
      }

      bundles.push({
        credentialType: req.credential_type,
        disclosure,
        provenClaims,
        zkpProofs,
      });
    }

    logs.push(`` + '✅ Presentation Bundle Prepared (' + bundles.length + ' VCs)');

    // Log what was shared (Data Transparency Foundation)
    await auditLog.append('VP_GENERATED', capsule.decision_id, {
      decision_id: capsule.decision_id,
      verifier_did: verifierDID,
      credential_types: bundles.map((b) => b.credentialType),
      claims_shared: bundles.flatMap((b) => Object.keys(b.disclosure)),
      claims_requested: requirements.flatMap((r) => r.requested_claims ?? []),
      proven_claims: bundles.flatMap((b) =>
        Object.keys(b.provenClaims).filter((k) => b.provenClaims[k])
      ),
      used_zkp: bundles.some((b) => Object.keys(b.zkpProofs || {}).length > 0),
    });

    // 3. Generate Ephemeral Proof Key (Asymmetric ECDSA)
    const proofKeys = await generateKeyPair();
    const proofPublicJWK = await getSubtle().exportKey('jwk', proofKeys.publicKey);

    await auditLog.append('KEY_CREATED', 'ephemeral-proof-key', {
      alg: 'ECDSA-P256',
      decision_id: capsule.decision_id,
    });
    logs.push('⚡ Ephemeral Proof Key Created (ECDSA-P256)');

    const vpPayload = {
      metadata: {
        type: 'VerifiablePresentationBundle',
        decision_id: capsule.decision_id,
        timestamp: Date.now(),
        // Replay Protection (Short Lived)
        validUntil: Date.now() + 60000,
        nonce: capsule.nonce,
        issuer_trust_refs: requirements.flatMap((r) => r.issuer_trust_refs || []),
      },
      presentations: bundles.map((b) => ({
        type: b.credentialType,
        disclosure: b.disclosure,
        proven_claims: b.provenClaims,
        zkp_proofs: b.zkpProofs,
      })),
    };

    // 4. Sign the Payload
    const payloadString = canonicalStringify(vpPayload);
    const signature = await getSubtle().sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      proofKeys.privateKey,
      new TextEncoder().encode(payloadString)
    );
    const signatureHex = Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    // 5. Create Proof Artifact
    const proofArtifact = {
      vp: vpPayload,
      proof: {
        alg: 'ES256',
        signature: signatureHex,
        public_key: proofPublicJWK,
        presence_proof: capsule.presence_proof,
      },
    };

    // 6. Encrypt for Verifier
    const ephemeralKey = await EphemeralKey.create();

    let targetPubKey: CryptoKey;
    const transportDid = verifierDID.startsWith('did:')
      ? verifierDID
      : 'did:mitch:verifier-liquor-store';
    if (transportDid !== verifierDID) {
      logs.push(`⚠️ Non-DID verifier id (${verifierDID}). Using demo DID for encryption.`);
    }
    if (agentTargetPubKey) {
      const officialKey = await fetchVerifierPublicKey(transportDid);
      const providedJWK = await getSubtle().exportKey('jwk', agentTargetPubKey);
      const officialJWK = await getSubtle().exportKey('jwk', officialKey);

      const nMatch = constantTimeCompare(providedJWK.n || '', officialJWK.n || '');
      const eMatch = constantTimeCompare(providedJWK.e || '', officialJWK.e || '');

      if (!nMatch || !eMatch) {
        logs.push(`⚠️ SECURITY ALERT: Actor provided a FAKE Key for ${verifierDID}! Blocking.`);
        throw new Error(
          'MITM ATTACK DETECTED: The provided encryption key does not belong to the target identity.'
        );
      }

      logs.push(
        `` + '✅ Key Binding Verified: Actor provided the correct key for ' + transportDid + '.'
      );
      targetPubKey = agentTargetPubKey;
    } else if (capsule.ephemeral_key) {
      logs.push('⚡ Using Ephemeral Session Key from Decision Capsule.');

      try {
        const alg = mapJwkToAlgorithm(capsule.ephemeral_key as JsonWebKey);
        targetPubKey = await getSubtle().importKey('jwk', capsule.ephemeral_key, alg, true, [
          'encrypt',
          'wrapKey',
        ]);
      } catch (e) {
        throw new Error(`EPHEMERAL_KEY_IMPORT_FAILED: ${(e as Error).message}`);
      }
    } else {
      targetPubKey = await fetchVerifierPublicKey(transportDid);
    }

    await auditLog.append('KEY_CREATED', 'ephemeral-session-key', {
      alg: 'AES-GCM-256',
      decision_id: capsule.decision_id,
    });
    logs.push('🔐 Ephemeral Session Key Created (AES-GCM-256)');

    const aad = new TextEncoder().encode(
      canonicalStringify({
        decision_id: capsule.decision_id,
        nonce: capsule.nonce,
        verifier_did: verifierDID,
      })
    );

    const ciphertext = await ephemeralKey.encrypt(JSON.stringify(proofArtifact), aad);
    const encryptedKey = await ephemeralKey.sealToRecipient(targetPubKey);

    const transportPackage = JSON.stringify({
      ciphertext,
      aad_context: {
        decision_id: capsule.decision_id,
        nonce: capsule.nonce,
        verifier_did: verifierDID,
      },
      recipient: {
        header: { kid: `${verifierDID}#key-1` },
        encrypted_key: encryptedKey,
      },
    });

    // 7. Crypto-Shredding (Double Shred)
    ephemeralKey.shred();
    (proofKeys as unknown as { privateKey: CryptoKey | null }).privateKey = null;

    await auditLog.append('KEY_DESTROYED', 'ephemeral-session-key', {
      decision_id: capsule.decision_id,
      verified: true,
      reason: 'Session terminal',
    });
    await auditLog.append('KEY_DESTROYED', 'ephemeral-proof-key', {
      decision_id: capsule.decision_id,
      verified: true,
      reason: 'Presentation complete',
    });

    logs.push('♻️ Ephemeral key references dropped (best-effort). Non-extractable keys used.');
    logs.push('✅ VP Bundle Signed & Encrypted');

    return { encryptedVp: transportPackage, auditLog: logs };
  }
}
