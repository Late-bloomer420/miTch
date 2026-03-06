/**
 * Tests: S-03 — Input Validation Schema (Whitelist-basiert)
 *
 * Attack pattern: Claim-Name Injection
 * Defense: Whitelist validation before any policy evaluation.
 *          Normalization (trim + lowercase) happens BEFORE comparison.
 */

import { describe, it, expect } from 'vitest';
import {
    validateClaimNames,
    normalizeClaimName,
    validateVerifierDID,
    validateVerifierPattern,
    sanitizeRequestedClaims,
} from '../input-validation';

describe('S-03: normalizeClaimName', () => {
    it('trims whitespace', () => {
        expect(normalizeClaimName('  age  ')).toBe('age');
    });

    it('lowercases', () => {
        expect(normalizeClaimName('AGE')).toBe('age');
    });

    it('returns null for empty string', () => {
        expect(normalizeClaimName('')).toBeNull();
    });

    it('returns null for whitespace-only string', () => {
        expect(normalizeClaimName('   ')).toBeNull();
    });
});

describe('S-03: validateClaimNames — whitelist', () => {
    it('accepts valid simple claim names', () => {
        const r = validateClaimNames(['age', 'birthdate', 'isOver18']);
        expect(r.valid).toBe(true);
        expect(r.normalized).toEqual(['age', 'birthdate', 'isover18']);
    });

    it('accepts names with underscore and hyphen', () => {
        const r = validateClaimNames(['first_name', 'birth-date']);
        expect(r.valid).toBe(true);
        expect(r.normalized).toEqual(['first_name', 'birth-date']);
    });

    it('rejects path traversal (../)', () => {
        const r = validateClaimNames(['../etc/passwd']);
        expect(r.valid).toBe(false);
        expect(r.rejected[0].claim).toBe('../etc/passwd');
    });

    it('rejects names with dot separators', () => {
        const r = validateClaimNames(['user.name']);
        expect(r.valid).toBe(false);
    });

    it('rejects names with slashes', () => {
        const r = validateClaimNames(['user/name']);
        expect(r.valid).toBe(false);
    });

    it('rejects names with wildcards (*)', () => {
        const r = validateClaimNames(['*']);
        expect(r.valid).toBe(false);
    });

    it('rejects names with dollar signs ($)', () => {
        const r = validateClaimNames(['$admin']);
        expect(r.valid).toBe(false);
    });

    it('rejects names starting with a digit', () => {
        const r = validateClaimNames(['1claim']);
        expect(r.valid).toBe(false);
    });

    it('rejects names that are too long', () => {
        const r = validateClaimNames(['a'.repeat(129)]);
        expect(r.valid).toBe(false);
    });

    it('rejects non-string entries', () => {
        const r = validateClaimNames([42, null, true] as unknown[]);
        expect(r.valid).toBe(false);
        expect(r.rejected).toHaveLength(3);
    });

    it('rejects more than 50 claims', () => {
        const r = validateClaimNames(Array.from({ length: 51 }, (_, i) => `claim${i}`));
        expect(r.valid).toBe(false);
        expect(r.rejected[0].reason).toMatch(/Too many claims/);
    });

    it('returns mixed: valid normalized + rejected', () => {
        const r = validateClaimNames(['age', '../etc/passwd', 'birthdate']);
        expect(r.normalized).toEqual(['age', 'birthdate']);
        expect(r.rejected).toHaveLength(1);
        expect(r.valid).toBe(false);
    });

    it('normalizes before validation (trim + lowercase)', () => {
        const r = validateClaimNames(['  AGE  ', '  IsOver18  ']);
        expect(r.valid).toBe(true);
        expect(r.normalized).toEqual(['age', 'isover18']);
    });
});

describe('S-03: validateVerifierDID', () => {
    it('accepts valid did:example:shop', () => {
        expect(validateVerifierDID('did:example:shop').valid).toBe(true);
    });

    it('accepts complex DID with colons', () => {
        expect(validateVerifierDID('did:peer:0z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp').valid).toBe(true);
    });

    it('rejects non-DID strings', () => {
        expect(validateVerifierDID('not-a-did').valid).toBe(false);
    });

    it('rejects empty string', () => {
        expect(validateVerifierDID('').valid).toBe(false);
    });

    it('rejects non-string input', () => {
        expect(validateVerifierDID(42).valid).toBe(false);
    });

    it('rejects DID with path traversal', () => {
        expect(validateVerifierDID('did:example:../../etc/passwd').valid).toBe(false);
    });
});

describe('S-03: validateVerifierPattern', () => {
    it('accepts wildcard *', () => {
        expect(validateVerifierPattern('*').valid).toBe(true);
    });

    it('accepts did:example:shop-* (glob patterns are valid in verifierPattern)', () => {
        expect(validateVerifierPattern('did:example:shop-*').valid).toBe(true);
    });

    it('accepts valid DID pattern without wildcard', () => {
        expect(validateVerifierPattern('did:example:shop').valid).toBe(true);
    });

    it('rejects empty string', () => {
        expect(validateVerifierPattern('').valid).toBe(false);
    });
});

describe('S-03: sanitizeRequestedClaims', () => {
    it('returns only valid normalized claims, drops malformed ones', () => {
        const result = sanitizeRequestedClaims(['age', '../attack', 'birthdate', 42]);
        expect(result).toEqual(['age', 'birthdate']);
    });

    it('returns [] for non-array input', () => {
        expect(sanitizeRequestedClaims('age')).toEqual([]);
        expect(sanitizeRequestedClaims(null)).toEqual([]);
    });
});
