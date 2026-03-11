/**
 * @module @mitch/predicates/nullifier
 *
 * Deterministic, unlinkable nullifier generation for ad-tech frequency capping.
 *
 * Formula (ADR-ADTECH-001):
 *   nullifier = SHA-256(user_seed || verifier_did || scope_id)
 *
 * The verifier_did is MANDATORY in the formula.
 * This ensures that two verifiers with the same campaign scope_id
 * receive different nullifiers for the same user — preventing cross-verifier correlation.
 *
 * Scope binding proves the nullifier belongs to a specific (verifier, scope) pair
 * without revealing the user_seed.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NullifierInput {
    /** 32 bytes derived from wallet master key via HKDF — never transmitted */
    userSeed: Uint8Array;
    /** Verifier's DID — must be included to prevent cross-verifier correlation */
    verifierDid: string;
    /** Campaign/ad-group scope identifier */
    scopeId: string;
}

export interface NullifierOutput {
    /** base64url-encoded SHA-256 nullifier */
    nullifier: string;
    /** base64url-encoded scope binding — proves nullifier belongs to (verifierDid, scopeId) */
    scopeBinding: string;
    /** The verifier DID bound into this nullifier */
    boundVerifierDid: string;
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Generate a deterministic, unlinkable nullifier.
 *
 * Same input always produces the same output (deterministic).
 * Different verifier DIDs produce different nullifiers for the same user + scope.
 * Different scope IDs produce different nullifiers for the same user + verifier.
 *
 * @throws {Error} if userSeed is not exactly 32 bytes
 */
export function generateNullifier(input: NullifierInput): NullifierOutput {
    if (input.userSeed.length !== 32) {
        throw new Error(`userSeed must be exactly 32 bytes, got ${input.userSeed.length}`);
    }

    // nullifier = SHA-256(user_seed || verifier_did || scope_id)
    const scopeBytes = utf8ToBytes(`${input.verifierDid}||${input.scopeId}`);
    const nullifierHash = sha256(concatBytes(input.userSeed, scopeBytes));
    const nullifier = base64UrlEncode(nullifierHash);

    // scope_binding = SHA-256(nullifier_bytes || scope_bytes)
    // Proves the nullifier was derived for this exact (verifier, scope) pair
    // without exposing user_seed
    const bindingHash = sha256(concatBytes(nullifierHash, scopeBytes));
    const scopeBinding = base64UrlEncode(bindingHash);

    return { nullifier, scopeBinding, boundVerifierDid: input.verifierDid };
}

/**
 * Verify that a nullifier was derived for a specific (verifierDid, scopeId) pair.
 *
 * Used by the wallet before presenting a response, and optionally by verifiers
 * to confirm the nullifier they received was bound to their scope.
 */
export function verifyNullifierScope(
    nullifier: string,
    verifierDid: string,
    scopeId: string,
    scopeBinding: string
): { valid: boolean; reason?: string } {
    try {
        const nullifierBytes = base64UrlDecode(nullifier);
        const scopeBytes = utf8ToBytes(`${verifierDid}||${scopeId}`);
        const expectedBinding = base64UrlEncode(sha256(concatBytes(nullifierBytes, scopeBytes)));

        if (expectedBinding !== scopeBinding) {
            return { valid: false, reason: 'Scope binding mismatch' };
        }
        return { valid: true };
    } catch (e) {
        return { valid: false, reason: `Verification error: ${String(e)}` };
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64UrlEncode(bytes: Uint8Array): string {
    // Node.js Buffer for encoding (predictable, available in test + server environments)
    return Buffer.from(bytes)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64UrlDecode(str: string): Uint8Array {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    return new Uint8Array(Buffer.from(padded, 'base64'));
}
