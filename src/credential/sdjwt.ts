/**
 * SD-JWT (Selective Disclosure JWT) — Phase 0 Implementation
 *
 * Implements draft-ietf-oauth-selective-disclosure-jwt
 * Simplified for PoC: Ed25519 signatures, JSON payloads.
 *
 * Flow:
 *   Issuer signs JWT with hashed disclosures
 *   → Wallet holds JWT + disclosures
 *   → Wallet selectively reveals only needed disclosures to verifier
 *   → Verifier checks signature + disclosed claims
 */

import { createHash, generateKeyPairSync, sign, verify, KeyObject } from "crypto";
import { randomBytes } from "crypto";

// ─── Types ───────────────────────────────────────────────────────

export interface SDJWTIssuerKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyId: string;
}

export interface Disclosure {
  salt: string;
  claimName: string;
  claimValue: string | number | boolean;
  encoded: string;   // base64url(JSON([salt, name, value]))
  hash: string;      // SHA-256 hash of encoded
}

export interface SDJWTCredential {
  /** The signed JWT (header.payload.signature) */
  jwt: string;
  /** All disclosures (wallet holds these, selectively reveals) */
  disclosures: Disclosure[];
  /** Credential metadata */
  meta: {
    credentialId: string;
    issuerId: string;
    subjectId: string;
    issuedAt: number;
    expiresAt: number;
    credentialType: string;
    statusListIndex?: number;
  };
}

export interface SDJWTPresentation {
  /** The original JWT */
  jwt: string;
  /** Only the disclosures the user chose to reveal */
  disclosedItems: Disclosure[];
  /** Binding proof (holder signed the verifier's nonce) */
  holderBinding?: string;
}

export interface SDJWTPayload {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  cnf?: { jwk: object };
  credential_type: string;
  credential_id: string;
  status_list?: { idx: number; uri: string };
  _sd: string[];          // hashes of disclosable claims
  _sd_alg: "sha-256";
}

// ─── Utilities ───────────────────────────────────────────────────

function base64url(data: string | Buffer): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function sha256(data: string): string {
  return base64url(createHash("sha-256").update(data, "utf8").digest());
}

function randomSalt(): string {
  return base64url(randomBytes(16));
}

// ─── Key Generation ──────────────────────────────────────────────

export function generateIssuerKey(keyId?: string): SDJWTIssuerKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey, keyId: keyId ?? `kid-${base64url(randomBytes(8))}` };
}

export function generateHolderKey(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

// ─── Disclosure Creation ─────────────────────────────────────────

function createDisclosure(claimName: string, claimValue: string | number | boolean): Disclosure {
  const salt = randomSalt();
  const arr = JSON.stringify([salt, claimName, claimValue]);
  const encoded = base64url(arr);
  const hash = sha256(encoded);
  return { salt, claimName, claimValue, encoded, hash };
}

// ─── Issuer: Sign Credential ─────────────────────────────────────

export interface IssueCredentialInput {
  issuerKey: SDJWTIssuerKey;
  issuerId: string;
  subjectId: string;
  claims: Record<string, string | number | boolean>;
  credentialType: string;
  expiresInSeconds?: number;
  statusListIndex?: number;
  statusListUri?: string;
  holderPublicKey?: KeyObject;
}

export function issueCredential(input: IssueCredentialInput): SDJWTCredential {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (input.expiresInSeconds ?? 90 * 24 * 3600); // default 90 days
  const credentialId = `cred-${base64url(randomBytes(12))}`;

  // Create disclosures for each claim
  const disclosures: Disclosure[] = [];
  for (const [name, value] of Object.entries(input.claims)) {
    disclosures.push(createDisclosure(name, value));
  }

  // Build JWT payload
  const payload: SDJWTPayload = {
    iss: input.issuerId,
    sub: input.subjectId,
    iat: now,
    exp,
    credential_type: input.credentialType,
    credential_id: credentialId,
    _sd: disclosures.map(d => d.hash),
    _sd_alg: "sha-256",
  };

  if (input.statusListIndex !== undefined && input.statusListUri) {
    payload.status_list = { idx: input.statusListIndex, uri: input.statusListUri };
  }

  if (input.holderPublicKey) {
    const jwk = input.holderPublicKey.export({ format: "jwk" });
    payload.cnf = { jwk };
  }

  // Sign
  const header = { alg: "EdDSA", typ: "sd+jwt", kid: input.issuerKey.keyId };
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const sigInput = `${headerEncoded}.${payloadEncoded}`;
  const signature = base64url(sign(null, Buffer.from(sigInput, "utf8"), input.issuerKey.privateKey));

  const jwt = `${sigInput}.${signature}`;

  return {
    jwt,
    disclosures,
    meta: {
      credentialId,
      issuerId: input.issuerId,
      subjectId: input.subjectId,
      issuedAt: now,
      expiresAt: exp,
      credentialType: input.credentialType,
      statusListIndex: input.statusListIndex,
    },
  };
}

// ─── Wallet: Create Selective Disclosure Presentation ─────────────

export interface PresentInput {
  credential: SDJWTCredential;
  /** Which claim names to disclose (only these are revealed) */
  disclose: string[];
  /** Verifier's nonce for holder binding */
  verifierNonce?: string;
  /** Holder's private key for key binding */
  holderPrivateKey?: KeyObject;
}

export function createPresentation(input: PresentInput): SDJWTPresentation {
  const disclosed = input.credential.disclosures.filter(
    d => input.disclose.includes(d.claimName)
  );

  let holderBinding: string | undefined;
  if (input.verifierNonce && input.holderPrivateKey) {
    const bindingPayload = {
      nonce: input.verifierNonce,
      iat: Math.floor(Date.now() / 1000),
    };
    const encoded = base64url(JSON.stringify(bindingPayload));
    const sig = base64url(sign(null, Buffer.from(encoded, "utf8"), input.holderPrivateKey));
    holderBinding = `${encoded}.${sig}`;
  }

  return {
    jwt: input.credential.jwt,
    disclosedItems: disclosed,
    holderBinding,
  };
}

// ─── Verifier: Verify Presentation ───────────────────────────────

export interface VerifyPresentationInput {
  presentation: SDJWTPresentation;
  issuerPublicKey: KeyObject;
  expectedIssuer?: string;
  expectedCredentialType?: string;
  requiredClaims?: string[];
  verifierNonce?: string;
  holderPublicKey?: KeyObject;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  claims: Record<string, string | number | boolean>;
  meta?: {
    issuer: string;
    credentialType: string;
    issuedAt: number;
    expiresAt: number;
  };
}

export function verifyPresentation(input: VerifyPresentationInput): VerifyResult {
  const { presentation, issuerPublicKey } = input;
  const fail = (reason: string): VerifyResult => ({ valid: false, reason, claims: {} });

  // 1. Parse JWT
  const parts = presentation.jwt.split(".");
  if (parts.length !== 3) return fail("invalid_jwt_structure");

  const [headerEnc, payloadEnc, signatureEnc] = parts;

  // 2. Verify issuer signature
  const sigInput = `${headerEnc}.${payloadEnc}`;
  const signature = Buffer.from(
    signatureEnc.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (signatureEnc.length % 4)) % 4),
    "base64"
  );

  const sigValid = verify(null, Buffer.from(sigInput, "utf8"), issuerPublicKey, signature);
  if (!sigValid) return fail("invalid_issuer_signature");

  // 3. Parse payload
  let payload: SDJWTPayload;
  try {
    payload = JSON.parse(base64urlDecode(payloadEnc));
  } catch {
    return fail("invalid_payload");
  }

  // 4. Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) return fail("credential_expired");

  // 5. Check issuer
  if (input.expectedIssuer && payload.iss !== input.expectedIssuer) {
    return fail("issuer_mismatch");
  }

  // 6. Check credential type
  if (input.expectedCredentialType && payload.credential_type !== input.expectedCredentialType) {
    return fail("credential_type_mismatch");
  }

  // 7. Verify each disclosed claim's hash is in _sd
  const claims: Record<string, string | number | boolean> = {};

  for (const disc of presentation.disclosedItems) {
    const computedHash = sha256(disc.encoded);
    if (!payload._sd.includes(computedHash)) {
      return fail(`disclosure_hash_mismatch:${disc.claimName}`);
    }

    // Verify disclosure content
    try {
      const arr = JSON.parse(base64urlDecode(disc.encoded));
      if (!Array.isArray(arr) || arr.length !== 3) return fail(`invalid_disclosure:${disc.claimName}`);
      claims[arr[1]] = arr[2];
    } catch {
      return fail(`invalid_disclosure_encoding:${disc.claimName}`);
    }
  }

  // 8. Check required claims are present
  if (input.requiredClaims) {
    for (const req of input.requiredClaims) {
      if (!(req in claims)) return fail(`missing_required_claim:${req}`);
    }
  }

  // 9. Verify holder binding (if provided)
  if (input.verifierNonce && presentation.holderBinding && input.holderPublicKey) {
    const bindParts = presentation.holderBinding.split(".");
    if (bindParts.length !== 2) return fail("invalid_holder_binding");

    const [bindPayloadEnc, bindSigEnc] = bindParts;
    const bindSig = Buffer.from(
      bindSigEnc.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (bindSigEnc.length % 4)) % 4),
      "base64"
    );
    const bindValid = verify(null, Buffer.from(bindPayloadEnc, "utf8"), input.holderPublicKey, bindSig);
    if (!bindValid) return fail("invalid_holder_binding_signature");

    try {
      const bindPayload = JSON.parse(base64urlDecode(bindPayloadEnc));
      if (bindPayload.nonce !== input.verifierNonce) return fail("holder_binding_nonce_mismatch");
    } catch {
      return fail("invalid_holder_binding_payload");
    }
  }

  return {
    valid: true,
    claims,
    meta: {
      issuer: payload.iss,
      credentialType: payload.credential_type,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    },
  };
}
