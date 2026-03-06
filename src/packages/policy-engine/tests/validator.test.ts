/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from 'vitest';
import { validatePolicy, checkManifestRollback } from '../src/policy-validator';
import { PolicyManifest } from '@mitch/shared-types';

const VALID_HASH = 'a'.repeat(64); // 64 hex chars

describe('Policy Validator (GDPR-by-Construction)', () => {

    const validPolicy: PolicyManifest = {
        version: '1.0',
        manifest_version: 1,
        manifest_hash: VALID_HASH,
        trustedIssuers: [{
            did: 'did:web:issuer.com',
            name: 'Good Issuer',
            credentialTypes: ['VerifiableCredential']
        }],
        rules: [{
            id: 'rule-1',
            verifierPattern: 'did:web:shop.com',
            allowedClaims: ['age'],
            priority: 10
        }],
        globalSettings: {
            blockUnknownVerifiers: true
        }
    };

    it('accepts a structurally valid policy', () => {
        const result = validatePolicy(validPolicy);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('rejects missing version', () => {
        const invalid: any = { ...validPolicy, version: undefined };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('SYNTAX: Missing policy version.');
    });

    it('rejects empty trusted issuers (vacuous policy)', () => {
        const invalid = { ...validPolicy, trustedIssuers: [] };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('AUTHORITY: No trusted issuers defined. Policy is vacuous.');
    });

    it('rejects invalid DID format in issuers', () => {
        const invalid = {
            ...validPolicy,
            trustedIssuers: [{
                did: 'not-a-did',
                name: 'Bad',
                credentialTypes: ['VC']
            }]
        };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('Invalid DID format'))).toBe(true);
    });

    it('rejects missing human-readable name for issuer (Transparency)', () => {
        const invalid = {
            ...validPolicy,
            trustedIssuers: [{
                did: 'did:web:ghost.com',
                name: '',
                credentialTypes: ['VC']
            }]
        };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('Missing human-readable name'))).toBe(true);
    });

    it('rejects rule without verifier pattern', () => {
        const invalid: any = {
            ...validPolicy,
            rules: [{
                id: 'bad-rule',
                allowedClaims: ['email']
            }]
        };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('Missing verifierPattern'))).toBe(true);
    });

    it('rejects vacuous rules (no allowed/proven/denied)', () => {
        const invalid = {
            ...validPolicy,
            rules: [{
                id: 'lazy-rule',
                verifierPattern: '*',
                allowedClaims: [],
                provenClaims: []
            }]
        };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('Vacuous rule'))).toBe(true);
    });

    it('rejects negative maxCredentialAgeDays', () => {
        const invalid = {
            ...validPolicy,
            rules: [{
                id: 'time-travel-rule',
                verifierPattern: '*',
                allowedClaims: ['email'],
                maxCredentialAgeDays: -1
            }]
        };
        const result = validatePolicy(invalid);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('maxCredentialAgeDays must be positive'))).toBe(true);
    });
});

describe('S-02: manifest_version + manifest_hash', () => {
    const base: PolicyManifest = {
        version: '1.0',
        manifest_version: 3,
        manifest_hash: 'b'.repeat(64),
        trustedIssuers: [{ did: 'did:web:issuer.com', name: 'Gov', credentialTypes: ['IDC'] }],
        rules: [{ id: 'r', verifierPattern: '*', allowedClaims: ['age'] }],
    };

    it('accepts valid manifest_version and manifest_hash', () => {
        expect(validatePolicy(base).valid).toBe(true);
    });

    it('rejects missing manifest_version', () => {
        const r = validatePolicy({ ...base, manifest_version: undefined });
        expect(r.valid).toBe(false);
        expect(r.errors.some(e => e.includes('manifest_version'))).toBe(true);
    });

    it('rejects manifest_version = 0', () => {
        const r = validatePolicy({ ...base, manifest_version: 0 });
        expect(r.valid).toBe(false);
        expect(r.errors.some(e => e.includes('manifest_version'))).toBe(true);
    });

    it('rejects non-integer manifest_version', () => {
        const r = validatePolicy({ ...base, manifest_version: 1.5 });
        expect(r.valid).toBe(false);
        expect(r.errors.some(e => e.includes('manifest_version'))).toBe(true);
    });

    it('rejects missing manifest_hash', () => {
        const r = validatePolicy({ ...base, manifest_hash: undefined });
        expect(r.valid).toBe(false);
        expect(r.errors.some(e => e.includes('manifest_hash'))).toBe(true);
    });

    it('rejects malformed manifest_hash (not 64 hex chars)', () => {
        const r = validatePolicy({ ...base, manifest_hash: 'tooshort' });
        expect(r.valid).toBe(false);
        expect(r.errors.some(e => e.includes('manifest_hash'))).toBe(true);
    });

    it('checkManifestRollback: accepts manifest with higher version', () => {
        const result = checkManifestRollback({ ...base, manifest_version: 5 }, 4);
        expect(result.ok).toBe(true);
    });

    it('checkManifestRollback: accepts manifest with equal version', () => {
        const result = checkManifestRollback({ ...base, manifest_version: 3 }, 3);
        expect(result.ok).toBe(true);
    });

    it('checkManifestRollback: rejects rollback (lower version)', () => {
        const result = checkManifestRollback({ ...base, manifest_version: 2 }, 5);
        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/Rollback attack/);
    });

    it('checkManifestRollback: rejects manifest without manifest_version', () => {
        const result = checkManifestRollback({ ...base, manifest_version: undefined }, 1);
        expect(result.ok).toBe(false);
    });
});
