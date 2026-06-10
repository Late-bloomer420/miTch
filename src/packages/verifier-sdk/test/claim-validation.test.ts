import { describe, it, expect } from 'vitest';
import { validateClaimRequest } from '../src/claim-validation';

describe('verifier-sdk / validateClaimRequest', () => {
    it('accepts a structurally valid request with a canonical claim', () => {
        const r = validateClaimRequest({ contractVersion: '1.0.0', claims: ['age_over_18'] });
        expect(r.valid).toBe(true);
        expect(r.claims).toEqual(['age_over_18']);
    });

    it('resolves deprecated aliases to canonical claims', () => {
        const r = validateClaimRequest({ contractVersion: '1.0.0', claims: ['isOver18', 'dateOfBirth'] });
        expect(r.valid).toBe(true);
        expect(r.claims).toEqual(['age_over_18', 'birthdate']);
    });

    it('rejects an unknown claim name (fail-closed vocabulary)', () => {
        const r = validateClaimRequest({ contractVersion: '1.0.0', claims: ['shoe_size'] });
        expect(r.valid).toBe(false);
        expect(r.errors.join(' ')).toMatch(/UNKNOWN_CLAIM/);
    });

    it('rejects a structurally malformed request (empty claims array)', () => {
        expect(validateClaimRequest({ contractVersion: '1.0.0', claims: [] }).valid).toBe(false);
    });

    it('rejects a wrong contractVersion', () => {
        expect(validateClaimRequest({ contractVersion: '0.9.0', claims: ['age_over_18'] }).valid).toBe(false);
    });

    it('rejects non-object / unexpected-property input', () => {
        expect(validateClaimRequest(null).valid).toBe(false);
        expect(validateClaimRequest('nope').valid).toBe(false);
        expect(validateClaimRequest({ contractVersion: '1.0.0', claims: ['age_over_18'], extra: 1 }).valid).toBe(false);
    });
});
