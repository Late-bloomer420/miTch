/**
 * @mitch/predicates - Verifier-Side Validation
 * 
 * Validates predicate results received from the wallet.
 * Checks for tampering, replay attacks, and policy violations.
 */

import {
    Predicate,
    PredicateRequest,
    hashPredicateAsync,
    hashRequestAsync,
    canonicalStringify
} from './canonical';

import {
    PredicateResult,
    PredicateVerificationResult
} from './types';

// ============================================================================
// ALLOWED PREDICATES (Verifier Policy)
// ============================================================================

/**
 * Build a set of allowed predicate hashes.
 * Verifier uses this to enforce policy.
 */
export async function buildAllowedPredicateSet(predicates: Predicate[]): Promise<Set<string>> {
    const hashes = new Set<string>();

    for (const pred of predicates) {
        const hash = await hashPredicateAsync(pred);
        hashes.add(hash);
    }

    return hashes;
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Verify a predicate result received from the wallet.
 */
export async function verifyPredicateResult(
    result: PredicateResult,
    originalRequest: PredicateRequest,
    allowedPredicateHashes: Set<string>,
    verifyFn: (data: string, signature: string) => Promise<boolean>,
    maxSkewMs: number = 5 * 60 * 1000 // Default 5 minute window
): Promise<PredicateVerificationResult> {
    const errors: string[] = [];
    const proof = result.proof;

    // Check 1: Verify binding (anti-poaching, anti-replay)
    if (proof.binding.verifierDid !== originalRequest.verifierDid) {
        errors.push(`Verifier DID mismatch: expected ${originalRequest.verifierDid}, got ${proof.binding.verifierDid}`);
    }

    if (proof.binding.nonce !== originalRequest.nonce) {
        errors.push(`Nonce mismatch: expected ${originalRequest.nonce}, got ${proof.binding.nonce}`);
    }

    // Check 2: Verify request hash (anti-tampering)
    const expectedRequestHash = await hashRequestAsync(originalRequest);
    if (proof.binding.requestHash !== expectedRequestHash) {
        errors.push(`Request hash mismatch: expected ${expectedRequestHash}, got ${proof.binding.requestHash}`);
    }

    // Check 3: Verify predicate hashes (policy enforcement)
    for (const evaluation of proof.evaluations) {
        if (!allowedPredicateHashes.has(evaluation.predicateHash)) {
            errors.push(`Unknown predicate hash: ${evaluation.predicateHash} not in allowed set`);
        }
    }

    // Check 4: Verify Timestamp (Freshness)
    const now = Date.now();
    const evaluatedAt = new Date(proof.evaluatedAt).getTime();
    if (isNaN(evaluatedAt)) {
        errors.push('Invalid evaluatedAt timestamp');
    } else {
        const age = now - evaluatedAt;
        if (Math.abs(age) > maxSkewMs) {
            errors.push(`Signature expired or clock skew too large (diff: ${age}ms, max: ${maxSkewMs}ms)`);
        }
    }

    // Check 5: Verify signature
    // Must reconstruct the payload string exactly as it was signed.
    const expectedPayloadString = canonicalStringify(proof);

    try {
        const signatureValid = await verifyFn(expectedPayloadString, result.signature);
        if (!signatureValid) {
            errors.push('Invalid signature');
        }
    } catch (e: any) {
        errors.push(`Signature verification error: ${e.message}`);
    }

    return {
        valid: errors.length === 0,
        errors
    };
}

/**
 * Extract and verify all predicates from a result.
 */
export async function extractAndVerifyPredicates(
    result: PredicateResult,
    allowedHashes: Set<string>
): Promise<PredicateVerificationResult> {
    const errors: string[] = [];

    for (const evaluation of result.proof.evaluations) {
        if (!allowedHashes.has(evaluation.predicateHash)) {
            errors.push(`Unknown predicate: ${evaluation.predicateId}`);
        }
    }

    return {
        valid: errors.length === 0,
        errors
    };
}
