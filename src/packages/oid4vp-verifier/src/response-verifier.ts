/**
 * OID4VP Verifier — Response validation
 */

import type { AuthorizationResponse, PresentationDefinition, ValidationResult } from '@mitch/oid4vp';
import { validateSubmission, parseVPToken } from '@mitch/oid4vp';

// ─── Nonce Store (in-memory, replace with persistent store in prod) ─

const usedNonces = new Map<string, number>(); // nonce → timestamp

/**
 * Check nonce has not been replayed.
 * TTL is 5 minutes.
 */
function checkNonce(nonce: string): boolean {
    const now = Date.now();
    // Purge expired
    for (const [n, ts] of usedNonces) {
        if (now - ts > 5 * 60 * 1000) usedNonces.delete(n);
    }
    if (usedNonces.has(nonce)) return false;
    usedNonces.set(nonce, now);
    return true;
}

// ─── Response Verifier ─────────────────────────────────────────────

export interface VerifyResponseOptions {
    response: AuthorizationResponse;
    expectedNonce: string;
    expectedState?: string;
    definition: PresentationDefinition;
    skipNonceCheck?: boolean; // for testing only
}

export interface VerificationResult {
    valid: boolean;
    credentials: string[];
    errors: string[];
}

/**
 * Verify an OID4VP Authorization Response.
 * Checks: nonce, state, submission matches definition, credential count.
 */
export function verifyAuthorizationResponse(
    opts: VerifyResponseOptions
): VerificationResult {
    const { response, expectedNonce, expectedState, definition, skipNonceCheck } = opts;
    const errors: string[] = [];

    // 1. Nonce check
    if (!skipNonceCheck && !checkNonce(expectedNonce)) {
        errors.push('Nonce replay detected');
    }

    // 2. State check
    if (expectedState && response.state !== expectedState) {
        errors.push(`State mismatch: expected ${expectedState}, got ${response.state}`);
    }

    // 3. Submission check
    const submissionResult = validateSubmission(response.presentation_submission, definition);
    if (!submissionResult.valid) {
        errors.push(...submissionResult.errors);
    }

    // 4. VP Token parse
    const { credentials } = parseVPToken(response.vp_token);
    const nonEmptyCredentials = credentials.filter(c => c.length > 0);
    if (nonEmptyCredentials.length === 0) {
        errors.push('VP Token contains no credentials');
    }

    // 5. Descriptor count matches credentials
    const descriptorCount = definition.input_descriptors.length;
    if (nonEmptyCredentials.length < descriptorCount) {
        errors.push(
            `Credential count mismatch: expected ≥${descriptorCount}, got ${nonEmptyCredentials.length}`
        );
    }

    return { valid: errors.length === 0, credentials: nonEmptyCredentials, errors };
}

/**
 * Verify that a presented credential satisfies a field constraint.
 * Simplified: checks that the credential string is non-empty (real impl
 * would decode SD-JWT and verify field paths).
 */
export function satisfiesConstraints(
    credential: string,
    definition: PresentationDefinition
): ValidationResult {
    if (!credential || credential.length < 10) {
        return { ok: false, error: 'Credential too short to be valid', code: 'INVALID_CREDENTIAL' };
    }

    // Check all input descriptors have a corresponding entry
    for (const desc of definition.input_descriptors) {
        if (desc.constraints?.fields) {
            for (const field of desc.constraints.fields) {
                if (!field.optional && field.path.length === 0) {
                    return { ok: false, error: `Empty path in descriptor ${desc.id}`, code: 'EMPTY_PATH' };
                }
            }
        }
    }

    return { ok: true };
}
