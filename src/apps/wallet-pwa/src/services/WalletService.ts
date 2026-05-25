import { PolicyEngine, type EvaluationContext } from '@mitch/policy-engine';
import { SecureStorage } from '@mitch/secure-storage';
import { AuditLog } from '@mitch/audit-log';
import {
  PolicyManifest,
  VerifierRequest,
  PolicyEvaluationResult,
  DecisionCapsule,
  AuditLogEntry,
  AuditLogExport,
  StoredCredentialMetadata,
  IdentityFirewallMetadata,
  IdentityPersistence,
  IdentityLinkability,
  IdentitySeverity,
} from '@mitch/shared-types';
import {
  EphemeralKey,
  deriveKeyFromPassword,
  generateKeyPair,
  canonicalStringify,
  RecoveryService,
  WebAuthnService,
  signData,
  resolveDID,
  detectKeyAlgorithm,
} from '@mitch/shared-crypto';

import { decodeMdoc as mdocDecodeMdoc, encode as mdocEncode } from '@mitch/mdoc';
import { DEMO_POLICY } from '../data/DemoPolicy';
import { ProofOfExistence } from './DocumentService';
import { PresentationBuilder, mapJwkToAlgorithm } from './PresentationBuilder';
import { SeedService, SEED_CREDENTIAL, MALICIOUS_CREDENTIAL } from './SeedService';
import { CredentialRepository } from './CredentialRepository';
import { evaluatePredicates, CommonPredicates, type PredicateRequest } from '@mitch/predicates';
import type { TrackingPoint } from './PrivacyAuditService';

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

const POLICY_STORAGE_KEY = 'mitch_user_policy';

// Default Policy for the PoC (Now persistent)
const DEFAULT_POLICY: PolicyManifest = DEMO_POLICY;

function sanitizeIdentityActorLabel(actor: string | undefined): string {
  const fallback = 'Unknown actor';
  const raw = (actor ?? '').trim();
  if (!raw) return fallback;

  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
      const parsed = new URL(raw);
      return parsed.hostname.substring(0, 80) || fallback;
    }
  } catch {
    // Fall through to conservative string cleanup.
  }

  const withoutQuery = raw.replace(/[?#].*$/, '');
  const withoutPath =
    withoutQuery.includes('/') && withoutQuery.includes('.')
      ? withoutQuery.split('/')[0]
      : withoutQuery;
  return (withoutPath.trim() || fallback).substring(0, 80);
}

function mapRiskLevel(riskLevel: TrackingPoint['riskLevel']): IdentitySeverity {
  if (riskLevel === 'HIGH') return 'critical';
  if (riskLevel === 'MEDIUM') return 'warning';
  return 'info';
}

function mapPersistence(tracker: TrackingPoint): IdentityPersistence {
  const persistences = tracker.dataExposed.map((d) => d.persistence);
  if (persistences.includes('CLOUD')) return 'cloud';
  if (persistences.includes('DEVICE')) return 'device';
  if (persistences.includes('SESSION')) return 'session';
  return 'unknown';
}

function mapLinkability(tracker: TrackingPoint): IdentityLinkability {
  const linkable = tracker.dataExposed.filter((d) => d.linkable);
  if (linkable.length === 0) return 'none';
  if (linkable.some((d) => d.persistence === 'CLOUD')) return 'cross_context';
  if (linkable.some((d) => d.persistence === 'DEVICE')) return 'cross_session';
  return 'session';
}

function mapTrackingPointToIdentityMetadata(
  decisionId: string,
  verifierDid: string | undefined,
  tracker: TrackingPoint
): IdentityFirewallMetadata {
  const base = {
    decision_id: decisionId,
    ...(verifierDid ? { verifier_did: verifierDid } : {}),
    actor_label: sanitizeIdentityActorLabel(tracker.actor),
    persistence: mapPersistence(tracker),
    linkability: mapLinkability(tracker),
    severity: mapRiskLevel(tracker.riskLevel),
    blocked: false as const,
    source: 'privacy_audit_service' as const,
  };

  switch (tracker.layer) {
    case 'BROWSER':
      return {
        ...base,
        access_type: 'browser_api',
        surface: 'navigator.userAgent',
        field_class: 'fingerprint',
      };
    case 'NETWORK':
      return {
        ...base,
        access_type: 'network_metadata',
        surface: 'network',
        field_class: 'metadata',
      };
    case 'OS':
      return {
        ...base,
        access_type: 'fingerprinting_signal',
        surface: 'unknown',
        field_class: 'fingerprint',
      };
    case 'SDK':
    case 'SERVER':
      return {
        ...base,
        access_type: 'tracker_domain',
        surface: 'unknown',
        field_class: 'tracking',
      };
  }
}

// Node-safe localStorage shim for non-browser environments (validation script)
const localStoreShim: Storage = (() => {
  try {
    if (typeof localStorage !== 'undefined') return localStorage;
  } catch (_: unknown) {
    /* no localStorage — fallback to in-memory */
  }
  const mem = new Map<string, string>();
  return {
    getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
    setItem: (k: string, v: string) => {
      mem.set(k, v);
    },
    removeItem: (k: string) => {
      mem.delete(k);
    },
    clear: () => {
      mem.clear();
    },
    key: (i: number) => Array.from(mem.keys())[i] ?? null,
    get length() {
      return mem.size;
    },
  } as unknown as Storage;
})();

export class WalletService {
  private storage: SecureStorage | null = null;
  private auditLog: AuditLog;
  private policyEngine: PolicyEngine | null = null;
  private policyPublicKey: CryptoKey | null = null;
  private policyPrivateKey: CryptoKey | null = null; // Identity Private Key (Phase 0)
  private initialized = false;
  private initPromise: Promise<void> | null = null;
  private credentialRepository: CredentialRepository | null = null;

  constructor() {
    this.auditLog = new AuditLog('user-wallet-001');
  }

  async initialize(pin: string, saltString: string = 'random-salt-per-user-v1'): Promise<void> {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      let retried = false;
      const run = async (): Promise<void> => {
        let step = 'start';
        const formatError = (err: unknown) => {
          if (err instanceof Error) return `${err.name}: ${err.message}`;
          return String(err);
        };
        try {
          // Secure Storage & Key Persistence
          console.log('🔐 Initializing Wallet with Secure Storage...');

          // 1. Derive Master Key from PIN (PBKDF2)
          // In prod, salt should be random (loaded from local storage) and stored.
          step = 'deriveMasterKey';
          const salt = new TextEncoder().encode(saltString);
          const masterKey = await deriveKeyFromPassword(pin, salt);

          // 2. Initialize Encrypted Storage
          step = 'initSecureStorage';
          this.storage = await SecureStorage.init(masterKey);
          this.credentialRepository = new CredentialRepository(this.storage);

          // Initialize Audit Keys (Truth Anchor) — persisted via SecureStorage
          step = 'initAuditKeys';
          const AUDIT_KEY_STORAGE_ID = '__mitch_audit_keys_v1';
          // Try to load persisted audit keys
          try {
            const storedAuditKeys = await this.storage!.load<{ created: string }>(
              AUDIT_KEY_STORAGE_ID
            );
            if (storedAuditKeys) {
              // Keys exist in storage — regenerate from same session
              // Note: WebCrypto non-extractable keys can't be serialized.
              // For PoC, we generate fresh keys but persist a marker.
              // Production would use key wrapping (wrapKey/unwrapKey).
              console.log('📦 Audit key marker found in storage (generating session keys)');
            }
          } catch (_: unknown) {
            // Storage error or first run — will generate fresh keys
          }

          const auditKeys = await generateKeyPair();
          this.auditLog.setAuditKeys(
            auditKeys.privateKey,
            auditKeys.publicKey,
            'audit-key-2026-v1'
          );

          // Persist audit key marker (for future key-wrapping implementation)
          try {
            await this.storage!.save(
              AUDIT_KEY_STORAGE_ID,
              { created: new Date().toISOString() },
              {
                issuer: 'did:mitch:self',
                type: ['SystemKey', 'AuditKey'],
                claims: ['created'],
                issuedAt: new Date().toISOString(),
              }
            );
          } catch (_: unknown) {
            console.warn('⚠️ Failed to persist audit key marker');
          }

          // 3. Generate Identity Keys (Phase 0: RAM Only - Ephemeral)
          const _IDENTITY_KEY_ID = 'identity-keys-v1';

          // Remove persistence check: Always generate fresh keys per session
          console.log('✨ Creating SESSION-SCOPED Identity Keypair (RAM only)...');
          step = 'generateIdentityKeys';

          const keys = await globalThis.crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false, // extractable: false (Secure Execution Environment emulation)
            ['sign', 'verify']
          );

          this.policyPrivateKey = keys.privateKey;
          this.policyPublicKey = keys.publicKey;

          console.warn('⚠️ Phase-0: Identity Keys are ephemeral and will be lost on reload.');

          // Initialize Policy Engine
          step = 'initPolicyEngine';
          this.policyEngine = new PolicyEngine(async (capsule: DecisionCapsule) => {
            const { wallet_attestation: _wallet_attestation, ...toSign } = capsule;
            const payload = canonicalStringify(toSign);
            // Consistent use of shared-crypto
            if (!this.policyPrivateKey) throw new Error('Identity Key not initialized');
            return signData(payload, this.policyPrivateKey);
          });

          step = 'seedCredentials';
          this.initialized = true;
          if (!this.storage) throw new Error('Storage not ready');
          await SeedService.ensureSeeded(this.storage);
          step = 'initPolicy';
          this.ensurePolicyInitialized();
        } catch (err) {
          throw new Error(`INIT_FAILED@${step}: ${formatError(err)}`);
        }
      };

      try {
        await run();
      } catch (err) {
        if (!retried) {
          retried = true;
          console.warn('[WalletService] Init failed. Resetting storage and retrying...', err);
          try {
            if (
              typeof (SecureStorage as unknown as { reset?: () => Promise<void> }).reset ===
              'function'
            ) {
              await (SecureStorage as unknown as { reset: () => Promise<void> }).reset();
            }
          } catch (resetErr) {
            console.warn(
              '[WalletService] Storage reset failed. Retrying without reset...',
              resetErr
            );
          }
          await run();
          return;
        }
        throw err;
      }
    })();

    try {
      await this.initPromise;
    } finally {
      this.initPromise = null;
    }
  }

  private ensurePolicyInitialized() {
    const existing = localStoreShim.getItem(POLICY_STORAGE_KEY);
    if (!existing) {
      this.savePolicy(DEFAULT_POLICY);
    } else {
      // Migration Logic
      try {
        const p = JSON.parse(existing);
        const currentVer = parseFloat(p.version || '1.0');
        const newVer = parseFloat(DEFAULT_POLICY.version);
        if (currentVer < newVer) {
          console.log(`Migrating Policy from ${currentVer} to ${newVer}`);
          this.savePolicy(DEFAULT_POLICY);
        }
      } catch {
        this.savePolicy(DEFAULT_POLICY);
      }
    }
  }

  getPolicy(): PolicyManifest {
    const raw = localStoreShim.getItem(POLICY_STORAGE_KEY);
    if (!raw) return DEFAULT_POLICY;

    const stored = JSON.parse(raw) as PolicyManifest;

    // Safe Policy Migration: Merge new rules, don't overwrite user preferences
    if (stored.version !== DEFAULT_POLICY.version) {
      console.log(
        `[WalletService] Policy version mismatch (${stored.version} → ${DEFAULT_POLICY.version}). Merging...`
      );

      // 1. Keep user's existing rules
      const userRuleIds = new Set(stored.rules.map((r) => r.id));

      // 2. Add new default rules that user doesn't have
      const newRules = DEFAULT_POLICY.rules.filter((r) => !userRuleIds.has(r.id));
      if (newRules.length > 0) {
        console.log(
          `[WalletService] Adding ${newRules.length} new rules: ${newRules.map((r) => r.id).join(', ')}`
        );
      }

      // 3. Add new trusted issuers
      const userIssuerDids = new Set(stored.trustedIssuers.map((i) => i.did));
      const newIssuers = DEFAULT_POLICY.trustedIssuers.filter((i) => !userIssuerDids.has(i.did));

      // 4. Merge: User rules + New rules, User issuers + New issuers
      const mergedPolicy: PolicyManifest = {
        ...stored,
        version: DEFAULT_POLICY.version, // Upgrade version
        rules: [...stored.rules, ...newRules],
        trustedIssuers: [...stored.trustedIssuers, ...newIssuers],
        globalSettings: { ...DEFAULT_POLICY.globalSettings, ...stored.globalSettings },
      };

      localStoreShim.setItem(POLICY_STORAGE_KEY, JSON.stringify(mergedPolicy));
      return mergedPolicy;
    }

    return stored;
  }

  savePolicy(policy: PolicyManifest) {
    localStoreShim.setItem(POLICY_STORAGE_KEY, JSON.stringify(policy));
  }

  async seedMalicious() {
    if (!this.credentialRepository) throw new Error('Storage not ready');
    await this.credentialRepository.addCredential(
      MALICIOUS_CREDENTIAL.id,
      MALICIOUS_CREDENTIAL.payload,
      {
        issuer: MALICIOUS_CREDENTIAL.issuer,
        type: MALICIOUS_CREDENTIAL.type,
        claims: MALICIOUS_CREDENTIAL.claims,
        issuedAt: MALICIOUS_CREDENTIAL.issuedAt,
      }
    );
  }

  /**
   * Stress Test - Corrupt a credential in storage to test integrity detection.
   */
  async corruptCredential() {
    if (!this.storage) throw new Error('Storage not ready');
    // Corrupt the 'vc-age-789' entry in the underlying storage (simulated bypass)
    (this.storage as unknown as { corruptEntry: (id: string) => void }).corruptEntry(
      SEED_CREDENTIAL.id
    );
  }

  /**
   * Stress Test - Evaluate against 500 complex rules.
   */
  async evaluateAgainstExplosion(
    request: VerifierRequest,
    context: EvaluationContext
  ): Promise<PolicyEvaluationResult> {
    if (!this.credentialRepository || !this.policyEngine) throw new Error('Wallet locked');

    const credentials = await this.credentialRepository.getCredentials();
    const basePolicy = this.getPolicy();

    const explodedRules = Array.from({ length: 500 }).map((_, i) => ({
      id: `rule-explosion-${i}`,
      verifierPattern: `service-${i}.com`,
      allowedClaims: ['email'],
      priority: 1,
    }));

    const stormPolicy: PolicyManifest = {
      ...basePolicy,
      rules: [...basePolicy.rules, ...explodedRules],
    };

    return this.policyEngine.evaluate(request, context, credentials, stormPolicy);
  }

  async splitMasterKey(): Promise<string[]> {
    // In a real app, we'd get the actual master key bits.
    // For the PoC, we use a placeholder that represents the entropy.
    const mockMasterKey = 'mitch-master-entropy-v1-highly-sensitive';
    return RecoveryService.splitMasterKey(mockMasterKey);
  }

  async recoverFromFragments(fragments: string[]): Promise<void> {
    const key = await RecoveryService.recover(fragments);
    console.log(`✅ Wallet Recovered! Key: ${key.substring(0, 5)}...`);
    // In prod, this would re-initialize SecureStorage
  }

  async evaluateRequest(
    request: VerifierRequest,
    context: EvaluationContext
  ): Promise<PolicyEvaluationResult> {
    if (!this.credentialRepository || !this.policyEngine) throw new Error('Wallet locked');

    const credentials = await this.credentialRepository.getCredentials();

    return this.policyEngine.evaluate(request, context, credentials, this.getPolicy());
  }

  /**
   * Verify the entire audit log chain integrity live.
   */
  async verifyAuditChain(): Promise<{ valid: boolean; error?: string }> {
    return this.auditLog.verifyChain();
  }

  async parseDeepLinkRequest(url: string): Promise<VerifierRequest | null> {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'mitch:') return null;

      const verifierDid = parsed.searchParams.get('verifier') || 'did:mitch:unknown';
      const nonce = parsed.searchParams.get('nonce') || crypto.randomUUID();
      const pubKeyB64 = parsed.searchParams.get('pub');

      const req: VerifierRequest = {
        verifierId: verifierDid,
        nonce,
        requirements: [
          {
            credentialType: 'VerifiableCredential',
            requestedClaims: ['age'],
            requestedProvenClaims: ['age >= 18'],
          },
        ],
      };

      if (pubKeyB64) {
        // T-88: Hydrate Ephemeral Key
        try {
          const jwk = JSON.parse(atob(pubKeyB64));
          // Use helper to import safely
          const alg = mapJwkToAlgorithm(jwk);
          const key = await globalThis.crypto.subtle.importKey('jwk', jwk, alg, true, [
            'encrypt',
            'wrapKey',
          ]);
          req.ephemeralResponseKey = key;
          console.log('⚡ Hydrated Ephemeral Key from Deep Link');
        } catch (e) {
          console.warn('Failed to hydrate ephemeral key from URL', e);
        }
      }

      return req;
    } catch (e) {
      console.error('Deep Link Parse Error', e);
      return null;
    }
  }

  async generatePresentation(
    capsule: DecisionCapsule,
    agentTargetPubKey?: CryptoKey // Force encryption to this key (Lufthansa) instead of DID resolution
  ): Promise<{ encryptedVp: string; auditLog: string[] }> {
    if (!this.storage) throw new Error('Wallet locked');
    return PresentationBuilder.generatePresentation(
      this.storage,
      this.auditLog,
      this.policyPublicKey,
      this.policyPrivateKey,
      capsule,
      agentTargetPubKey
    );
  }

  /**
   * Store a credential received from an OID4VCI issuer.
   * Call after parsing the JWT credential response from POST /credential.
   */
  async addIssuedCredential(
    id: string,
    subject: Record<string, unknown>,
    issuerDid: string
  ): Promise<void> {
    if (!this.storage || !this.credentialRepository) throw new Error('Wallet locked');
    await SeedService.ensureSeeded(this.storage);
    const meta: StoredCredentialMetadata = {
      id,
      issuer: issuerDid,
      type: ['VerifiableCredential', 'AgeCredential'],
      issuedAt: new Date().toISOString(),
      claims: Object.keys(subject),
    };
    await this.credentialRepository.addCredential(id, subject, meta);
    await this.auditLog.append('KEY_USED', id, { context: 'OID4VCI_ISSUANCE', issuer: issuerDid });
  }

  /**
   * Store an mdoc credential (ISO 18013-5) received via OID4VCI.
   *
   * The credential is stored as a JSON-serializable wrapper containing
   * the raw CBOR bytes (base64-encoded), docType, and extracted claims.
   * Format is tagged as 'mso_mdoc' in metadata.
   */
  async addMdocCredential(
    id: string,
    mdocCborBytes: Uint8Array,
    docType: string,
    issuerDid: string,
    claimNames: string[]
  ): Promise<void> {
    if (!this.storage || !this.credentialRepository) throw new Error('Wallet locked');
    await SeedService.ensureSeeded(this.storage);

    // Store as JSON wrapper with base64-encoded CBOR for SecureStorage compatibility
    const payload = {
      _mdoc: true,
      docType,
      cborBase64: uint8ArrayToBase64(mdocCborBytes),
    };

    const meta: StoredCredentialMetadata = {
      id,
      issuer: issuerDid,
      type: ['VerifiableCredential', docType],
      issuedAt: new Date().toISOString(),
      claims: claimNames,
      format: 'mso_mdoc',
    };

    await this.credentialRepository.addCredential(id, payload, meta);
    await this.auditLog.append('KEY_USED', id, {
      context: 'MDOC_ISSUANCE',
      issuer: issuerDid,
      docType,
    });
  }

  /**
   * Record PII-minimal Identity Firewall transparency events for a proof flow.
   */
  async recordIdentityFirewallEvents(
    decisionId: string | undefined,
    verifierDid: string | undefined,
    trackers: TrackingPoint[]
  ): Promise<AuditLogEntry[]> {
    if (!decisionId) return [];

    const entries: AuditLogEntry[] = [];
    for (const tracker of trackers) {
      const metadata = mapTrackingPointToIdentityMetadata(decisionId, verifierDid, tracker);
      const entry = await this.auditLog.append(
        'IDENTITY_ACCESS_DETECTED',
        `identity-firewall:${metadata.access_type}`,
        metadata as unknown as Record<string, unknown>
      );
      entries.push(entry);
    }

    return entries;
  }

  /**
   * Get recent logs for the UI.
   */
  getRecentAuditLogs(limit: number = 5): AuditLogEntry[] {
    return this.auditLog.getRecentEntries(limit);
  }

  /**
   * Export a signed report of all wallet activities.
   * This is the "Beweislast-Umkehr" (Reverse Onus of Proof) artifact.
   */
  async exportAuditReport(): Promise<AuditLogExport> {
    return this.auditLog.exportReport();
  }

  async syncAuditToL2() {
    return this.auditLog.syncToL2();
  }

  /**
   * Handle Recovery Actions triggered by Policy Denial
   */
  async handleAction(
    action: import('@mitch/shared-types').DenialAction
  ): Promise<{ success: boolean; message: string }> {
    console.log(`[Action Handler] Processing: ${action.type}`);

    switch (action.type) {
      case 'LOAD_CREDENTIAL':
        // Simulate launching OID4VCI (dependency)
        console.log(`[OID4VCI] Launching wizard for target: ${action.target}`);
        return { success: true, message: 'OID4VCI Wizard Started' };

      case 'OVERRIDE_WITH_CONSENT':
        // In a real app, this would grant temporary permission
        console.log(`[Override] User accepted risk for action: ${action.id}`);
        await this.auditLog.append('POLICY_EVALUATED', action.id, {
          result: 'OVERRIDE',
          context: 'USER_CONSENT_GRANTED',
        });
        return { success: true, message: 'Policy Override Granted' };

      case 'CONTACT_VERIFIER':
        console.log(`[Contact] Opening support channel for ${action.target}`);
        // window.open('mailto:support@verifier.com');
        return { success: true, message: 'Support Channel Opened' };

      case 'LEARN_MORE':
        console.log(`[Learn] Navigating to: ${action.target}`);
        // window.open(action.target, '_blank');
        return { success: true, message: 'Documentation Opened' };

      case 'REPORT_ISSUE':
        console.log('[Report] Logging issue to support queue.');
        return { success: true, message: 'Issue Reported' };

      default:
        console.warn(`[Handler] Unknown action type: ${action.type}`);
        return { success: false, message: 'Action not realized' };
    }
  }

  /**
   * Add a credential to the wallet (persisted encrypted in SecureStorage).
   */
  async addCredential(
    id: string,
    payload: Record<string, unknown>,
    metadata: { issuer: string; type: string[]; claims: string[]; issuedAt: string }
  ): Promise<void> {
    if (!this.credentialRepository) throw new Error('Wallet locked');
    await this.credentialRepository.addCredential(id, payload, metadata);
  }

  /**
   * Delete a credential from the wallet.
   * Returns true if the credential existed and was removed, false otherwise.
   */
  async deleteCredential(id: string): Promise<boolean> {
    if (!this.credentialRepository) throw new Error('Wallet locked');
    return this.credentialRepository.deleteCredential(id);
  }

  /**
   * Get all credential metadata (without decrypting payloads).
   */
  async getCredentials(): Promise<StoredCredentialMetadata[]> {
    if (!this.credentialRepository) throw new Error('Wallet locked');
    return this.credentialRepository.getCredentials();
  }

  /**
   * Load a specific credential's decrypted payload.
   */
  async loadCredential<T = Record<string, unknown>>(id: string): Promise<T | null> {
    if (!this.credentialRepository) throw new Error('Wallet locked');
    return this.credentialRepository.loadCredential<T>(id);
  }

  /**
   * Get raw encrypted document for a credential (test/debug only).
   */
  async getRawCredentialDocument(id: string) {
    if (!this.credentialRepository) throw new Error('Wallet locked');
    return this.credentialRepository.getRawCredentialDocument(id);
  }

  /**
   * Sign arbitrary data (e.g., document hashes) using the persistent Identity Key.
   * This differs from ephemeral VP signing - these signatures are meant to persist.
   *
   * NOTE: This returns a "Compact-like proof token" (not RFC7515 JWS).
   * For production, implement proper ES256 JWS with base64url encoding.
   */
  async signData(payload: ProofOfExistence): Promise<{ proofToken: string; auditLog: string[] }> {
    if (!this.storage) throw new Error('Wallet locked');

    // Access audit keys via internal property (AuditLog doesn't expose getAuditKeys)
    // TODO: Separate identity signing key from audit key (see security review)
    const auditLogInternal = this.auditLog as unknown as {
      privateKey?: CryptoKey;
      publicKey?: CryptoKey;
    };
    const auditKeys = auditLogInternal.privateKey
      ? { privateKey: auditLogInternal.privateKey, publicKey: auditLogInternal.publicKey }
      : null;

    if (!auditKeys?.privateKey) throw new Error('Identity keys not available');

    const logs: string[] = [];
    const content = canonicalStringify(payload);

    // Sign with ECDSA
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      auditKeys.privateKey,
      new TextEncoder().encode(content)
    );

    const signatureHex = Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    // Create Proof Token (Compact-like format, NOT RFC7515 JWS)
    // Format: base64(header).base64(payload).hex(signature)
    // Note: Uses standard Base64, not Base64URL; signature is hex, not base64url(r|s)
    const header = canonicalStringify({
      alg: 'ES256-PoC',
      kid: 'did:mitch:user-wallet-001#audit-key',
    });
    const protectedHeader = btoa(header);
    const encodedPayload = btoa(content);

    const proofToken = `${protectedHeader}.${encodedPayload}.${signatureHex}`;

    await this.auditLog.append('KEY_USED', payload.hash, {
      context: 'DOCUMENT_SIGNING',
      description: payload.description,
      type: payload.mediaType,
    });

    logs.push(`✅ Document Signed: ${payload.description}`);
    logs.push(`📝 Hash: ${payload.hash.substring(0, 8)}...`);
    logs.push('🔑 Key: Persistent Identity Key');
    logs.push('⚠️  PoC Token Format (not RFC7515 JWS)');

    return { proofToken, auditLog: logs };
  }
}
