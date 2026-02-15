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

// Phase 0: KeyGuardian (replaces tee-attestation)
export * from './types/KeyProtectionLevel.js';
export * from './interfaces/KeyGuardian.js';
export * from './SoftwareKeyGuardian.js';
