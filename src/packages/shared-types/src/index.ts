/**
 * Shared Type Definitions for miTch PoC
 * Barrel export for all type modules
 */

// W3C Verifiable Credentials
export * from './vc.js';

// Policy Engine
export * from './policy.js';

// Audit Logging
export * from './audit.js';

// OID4VCI API Contracts
export * from './oid4vci.js';

// EHDS Schemas
export * from './health.js';

// ZKP Predicate Schemas
export * from './predicates.js';

// Anchor Service Types
export * from './anchor.js';
/**
 * Result type for operations that can fail
 */
export type Result<T, E = Error> =
    | { ok: true; value: T }
    | { ok: false; error: E };

/**
 * Async result
 */
export type AsyncResult<T, E = Error> = Promise<Result<T, E>>;

/**
 * Optional with explicit undefined
 */
export type Maybe<T> = T | undefined;

/**
 * Branded type for type-safe IDs
 */
export type Brand<T, B> = T & { __brand: B };

/**
 * Credential ID (branded string for type safety)
 */
export type CredentialId = Brand<string, 'CredentialId'>;

/**
 * Key ID (branded string)
 */
export type KeyId = Brand<string, 'KeyId'>;

/**
 * Hash (always lowercase hex string)
 */
export type Hash = Brand<string, 'SHA256Hash'>;
