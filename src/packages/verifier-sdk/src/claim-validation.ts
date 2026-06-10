/**
 * @askmi/verifier-sdk — Claim request validation (contract ingress guard)
 *
 * ajv-backed runtime validation of external verifier claim requests against the
 * versioned JSON Schema (the source of truth in @askmi/shared-types). The ajv
 * dependency lives HERE, not in shared-types, so the shared types stay a
 * zero-runtime-dependency leaf (it is imported by the browser wallet bundle).
 *
 * Two-stage, fail-closed:
 *   1. ajv — structural validation (shape, contractVersion, non-empty claims).
 *   2. resolveClaim — vocabulary validation (alias→canonical, reject unknown).
 */

import Ajv2020 from 'ajv/dist/2020.js';
import {
    CLAIM_CONTRACT_SCHEMA_V1,
    resolveClaim,
    UnknownClaimError,
    type CanonicalClaim,
} from '@askmi/shared-types';

const ajv = new Ajv2020({ allErrors: true });
const validateStructure = ajv.compile(CLAIM_CONTRACT_SCHEMA_V1);

export interface ClaimRequestValidation {
    valid: boolean;
    /** Canonical claim names, present only when `valid` is true. */
    claims?: CanonicalClaim[];
    errors: string[];
}

/**
 * Validate an untrusted claim request. Returns the resolved canonical claims on
 * success; on failure returns `valid: false` with privacy-safe error strings
 * (no echo of unexpected input values).
 */
export function validateClaimRequest(input: unknown): ClaimRequestValidation {
    if (!validateStructure(input)) {
        const errors = (validateStructure.errors ?? []).map(
            (e) => `${e.instancePath || '(root)'} ${e.message ?? 'invalid'}`.trim(),
        );
        return { valid: false, errors: errors.length ? errors : ['INVALID_REQUEST'] };
    }

    const { claims: requested } = input as { claims: string[] };
    const claims: CanonicalClaim[] = [];
    const errors: string[] = [];

    for (const name of requested) {
        try {
            claims.push(resolveClaim(name));
        } catch (e) {
            errors.push(e instanceof UnknownClaimError ? e.message : 'INVALID_CLAIM');
        }
    }

    if (errors.length) return { valid: false, errors };
    return { valid: true, claims, errors: [] };
}
