export * from './platform';
export * from './keys';
export * from './hashing';
export * from './encryption';
export * from './signing';
export * from './ephemeral';
export type { IEphemeralKey } from './interfaces/IEphemeralKey';
export * from './recovery';
export * from './secure-buffer';
export * from './webauthn';
export * from './did';
export * from './nonce-store';
export * from './presentation-binding';
export * from './did-verification';
export * from './jwe'; // G-08: JWE-encrypted credentials at rest
export * from './pairwise-did'; // Spec 111: Pairwise Ephemeral DIDs

// Phase 0: KeyGuardian (replaces tee-attestation)
export * from './types/KeyProtectionLevel.js';
export * from './interfaces/KeyGuardian.js';
export * from './SoftwareKeyGuardian.js';

export * from './did-quorum';
export * from './crypto-agility';
export * from './sd-jwt-vc'; // E-10: SD-JWT VC Compliance (draft-ietf-oauth-sd-jwt-vc-11)
export * from './dpop'; // E-05: DPoP (RFC 9449)
export * from './brainpool'; // C-01: Brainpool Curves (BSI/SOG-IS)
export * from './mac-verify'; // C-02: MAC-based Verification (ECDH + HMAC-SHA2)
export * from './pqc';        // Spec 93: PQC live — ML-DSA, ML-KEM, SLH-DSA, Hybrid
