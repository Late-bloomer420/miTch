export * from './platform';
export * from './keys';
export * from './hashing';
export * from './encryption';
export * from './signing';
export * from './ephemeral';
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
