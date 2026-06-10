import { describe, it, expect } from 'vitest';
import {
    computeAgeOnDate,
    evaluateAgeOver18,
    buildAgeOver18Predicate,
} from './age-contract';
import { hashPredicate } from './canonical';

const ASOF = new Date('2026-06-10T00:00:00Z');

describe('age-contract / computeAgeOnDate — deterministic via injected asOf', () => {
    it('computes age relative to the injected asOf date, not the wall clock', () => {
        expect(computeAgeOnDate('2000-06-10', ASOF)).toBe(26);
    });

    it('does not count a birthday that has not yet occurred in the asOf year', () => {
        expect(computeAgeOnDate('2000-06-11', ASOF)).toBe(25);
    });

    it('returns NaN for a malformed birthdate (caller fails closed)', () => {
        expect(Number.isNaN(computeAgeOnDate('not-a-date', ASOF))).toBe(true);
    });
});

describe('age-contract / evaluateAgeOver18 — boundary determinism', () => {
    it('is true exactly on the 18th birthday', () => {
        expect(evaluateAgeOver18('2008-06-10', ASOF)).toBe(true);
    });

    it('is false the day before the 18th birthday', () => {
        expect(evaluateAgeOver18('2008-06-11', ASOF)).toBe(false);
    });

    it('fails closed on a malformed birthdate', () => {
        expect(evaluateAgeOver18('', ASOF)).toBe(false);
    });
});

describe('age-contract / buildAgeOver18Predicate — canonical & stable', () => {
    it('carries the canonical age_over_18 id and EUDI credential type', () => {
        const p = buildAgeOver18Predicate();
        expect(p.id).toBe('age_over_18');
        expect(p.credentialTypes).toContain('urn:eudi:pid:1');
    });

    it('derives the birthdate path from the contract format binding', () => {
        const clause = buildAgeOver18Predicate().expression.clauses[0] as { path: string; value: unknown };
        expect(clause.path).toBe('birthdate');
        expect(clause.value).toBe(18);
    });

    it('produces a stable canonical hash across builds', () => {
        expect(hashPredicate(buildAgeOver18Predicate())).toBe(
            hashPredicate(buildAgeOver18Predicate()),
        );
    });
});
