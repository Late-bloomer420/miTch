/**
 * @askmi/predicates — Canonical age predicate (contract-bound, deterministic)
 *
 * The canonical `age_over_18` predicate for the EUDI-aligned claim contract
 * (G-100.2). Two determinism guarantees that the ad-hoc `CommonPredicates`
 * lacked:
 *   1. Age is computed against an INJECTED `asOf` date, never the wall clock —
 *      so boundary cases (the 18th birthday) are reproducible in tests and CI.
 *   2. The predicate id / paths come from the versioned contract, not free-text.
 *
 * Wiring of the live evaluation path onto this builder happens in PR-B; this
 * module is additive (no existing flow changes).
 */

import { getFormatBinding } from '@askmi/shared-types';
import type { Predicate } from './canonical';

/**
 * Calendar age of `birthdateISO` (YYYY-MM-DD) as of `asOf`, compared purely in
 * UTC calendar terms so the result never depends on the runner's timezone.
 * Returns `NaN` for a malformed birthdate (callers treat NaN as fail-closed).
 */
export function computeAgeOnDate(birthdateISO: string, asOf: Date): number {
    const [by, bm, bd] = birthdateISO.split('T')[0].split('-').map(Number);
    if (!by || !bm || !bd) return NaN;

    const ay = asOf.getUTCFullYear();
    const am = asOf.getUTCMonth() + 1;
    const ad = asOf.getUTCDate();

    let age = ay - by;
    if (am < bm || (am === bm && ad < bd)) age--;
    return age;
}

/** Canonical `age_over_18` result for a birthdate at a fixed evaluation date. Fail-closed. */
export function evaluateAgeOver18(birthdateISO: string, asOf: Date): boolean {
    const age = computeAgeOnDate(birthdateISO, asOf);
    return Number.isFinite(age) && age >= 18;
}

/**
 * Build the canonical `age_over_18` predicate. Id and birthdate path are derived
 * from the contract (canonical name + SD-JWT-VC format binding), giving a stable
 * canonical hash for request binding.
 */
export function buildAgeOver18Predicate(): Predicate {
    const birthdateBinding = getFormatBinding('birthdate', 'sd-jwt-vc');
    /* c8 ignore next */
    if (!birthdateBinding) throw new Error('CONTRACT_ERROR: missing sd-jwt-vc birthdate binding');

    return {
        id: 'age_over_18',
        description: 'Holder is at least 18 years old',
        credentialTypes: [birthdateBinding.credentialType],
        expression: {
            logic: 'and',
            clauses: [
                {
                    path: birthdateBinding.locator,
                    op: 'gte',
                    type: 'age_years',
                    value: 18,
                },
            ],
        },
    };
}
