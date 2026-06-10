import { describe, it, expect } from 'vitest';
import { evaluatePredicates } from './evaluate';
import { buildAgeOver18Predicate } from './age-contract';
import type { PredicateRequest } from './canonical';

const sign = async () => 'test-signature';

function ageRequest(): PredicateRequest {
    return {
        verifierDid: 'did:example:liquor-store',
        nonce: 'nonce-asof',
        purpose: 'Age Verification',
        timestamp: '2026-06-10T00:00:00Z',
        predicates: [buildAgeOver18Predicate()],
    };
}

// These dates are chosen so the outcome DIFFERS from the real wall clock — the
// test only passes if `asOf` is actually honoured (not `new Date()`).
describe('evaluatePredicates — deterministic age via injected asOf', () => {
    it('uses a FUTURE asOf: a 14-year-old today is over 18 as of 2030', async () => {
        const asOf = new Date('2030-06-10T00:00:00Z');
        const res = await evaluatePredicates({ birthdate: '2012-06-10' }, ageRequest(), sign, asOf);
        expect(res.proof.allPassed).toBe(true); // wall-clock 2026 ⇒ age 14 ⇒ would be false
    });

    it('uses a PAST asOf: an adult today is under 18 as of 2025', async () => {
        const asOf = new Date('2025-06-10T00:00:00Z');
        const res = await evaluatePredicates({ birthdate: '2008-06-10' }, ageRequest(), sign, asOf);
        expect(res.proof.allPassed).toBe(false); // wall-clock 2026 ⇒ age 18 ⇒ would be true
    });

    it('is reproducible across 10 runs with the same asOf', async () => {
        const asOf = new Date('2030-06-10T00:00:00Z');
        const results = await Promise.all(
            Array.from({ length: 10 }, () =>
                evaluatePredicates({ birthdate: '2012-06-10' }, ageRequest(), sign, asOf),
            ),
        );
        expect(results.every((r) => r.proof.allPassed === true)).toBe(true);
    });
});
