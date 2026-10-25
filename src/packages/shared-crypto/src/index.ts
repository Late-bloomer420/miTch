export * from './platform.js';
export * from './keys.js';
export * from './hashing.js';
export * from './multibase.js';
export * from './encryption.js';
export * from './signing.js';
export * from './ephemeral.js';
export type { IEphemeralKey } from './interfaces/IEphemeralKey.js';
export * from './recovery.js';
export * from './secure-buffer.js';
export * from './webauthn.js';
export * from './did.js';
export * from './nonce-store.js';
export * from './presentation-binding.js';
export * from './did-verification.js';
export * from './jwe.js'; // G-08: JWE-encrypted credentials at rest
export * from './pairwise-did.js'; // Spec 111: Pairwise Ephemeral DIDs

// Phase 0: KeyGuardian (replaces tee-attestation)
export * from './types/KeyProtectionLevel.js';
export * from './interfaces/KeyGuardian.js';
export * from './SoftwareKeyGuardian.js';
export * from './IdentityKeyGuardian.js';

export * from './did-quorum.js';
export * from './crypto-agility.js';
export * from './sd-jwt-vc.js'; // E-10: SD-JWT VC Compliance (draft-ietf-oauth-sd-jwt-vc-11)
export type { JWK } from 'jose';
export * from './holder-binding.js'; // U-11: Ephemeral Holder Binding (Proof-Randomization)
export * from './dpop.js'; // E-05: DPoP (RFC 9449)
export * from './brainpool.js'; // C-01: Brainpool Curves (BSI/SOG-IS)
export * from './mac-verify.js'; // C-02: MAC-based Verification (ECDH + HMAC-SHA2)
export * from './status-resolver.js'; // E-30: Live StatusList Revocation Check
export * from './trust-list-resolver.js'; // E-40: EUDI Trust List (TSL) Integration
export * from './pqc.js';        // Spec 93: PQC live — ML-DSA, ML-KEM, SLH-DSA, Hybrid
