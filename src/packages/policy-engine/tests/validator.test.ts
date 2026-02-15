import { describe, it, expect } from 'vitest';
import { validatePolicy } from '../src/policy-validator';
import { PolicyManifest } from '@mitch/shared-types';

describe('Policy Validator (GDPR-by-Construction)', () => {

    const validPolicy: PolicyManifest = {
        version: '1.0',
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
