
import { describe, test, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../src/engine';
import type { VerifierRequest, PolicyManifest, StoredCredentialMetadata } from '@mitch/shared-types';

const baseContext: EvaluationContext = {
    timestamp: Date.now(),
    userDID: 'did:example:holder',
};

const testPolicy: PolicyManifest = {
    version: '1.0',
    trustedIssuers: [
        {
            did: 'did:example:gov-issuer',
            name: 'Gov ID',
            credentialTypes: ['AgeCredential']
        }
    ],
    rules: [
        {
            id: 'rule-1',
            verifierPattern: 'liquor-store-*',
            allowedClaims: ['isOver18'],
            deniedClaims: ['name'], // Explicitly denied
            requiresTrustedIssuer: true,
            priority: 10,
            maxCredentialAgeDays: 365
        },
        {
            id: 'rule-consent',
            verifierPattern: 'sensitive-service',
            allowedClaims: ['health'],
            requiresUserConsent: true,
            priority: 10
        }
    ],
    globalSettings: {
        blockUnknownVerifiers: true
    }
};

const validCred: StoredCredentialMetadata = {
    id: 'cred-1',
    issuer: 'did:example:gov-issuer',
    type: ['AgeCredential'],
    issuedAt: new Date().toISOString(),
    claims: ['isOver18']
};

describe('PolicyEngine - Comprehensive Logic', () => {
    const engine = new PolicyEngine();

    test('DENY: Claim explicitly denied', async () => {
        const req: VerifierRequest = { verifierId: 'liquor-store-1', requestedClaims: ['name'] };
        const res = await engine.evaluate(req, baseContext, [validCred], testPolicy);
        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.CLAIM_NOT_ALLOWED);
    });

    test('ALLOW: Valid request with trusted issuer', async () => {
        const req: VerifierRequest = { verifierId: 'liquor-store-1', requestedClaims: ['isOver18'] };
        const res = await engine.evaluate(req, baseContext, [validCred], testPolicy);
        expect(res.verdict).toBe('ALLOW');
        expect(res.reasonCodes).toContain(ReasonCode.RULE_MATCHED);
        expect(res.decisionCapsule).toBeDefined();
        expect(res.decisionCapsule?.allowed_claims).toEqual(['isOver18']);
    });

    test('DENY: Issuer not trusted', async () => {
        const untrustedCred: StoredCredentialMetadata = {
            ...validCred,
            id: 'bad-cred',
            issuer: 'did:example:untrusted-issuer'
        };
        const req: VerifierRequest = { verifierId: 'liquor-store-1', requestedClaims: ['isOver18'] };
        const res = await engine.evaluate(req, baseContext, [untrustedCred], testPolicy);
        // Should find credential unsuitable due to UNTRUSTED_ISSUER
        // Or RULE matched but no suitable credential found.
        expect(res.verdict).toBe('DENY');
        // The current logic returns NO_SUITABLE_CREDENTIAL if the filter removes it.
        // Reason details inside the filter logic should bubble up if possible.
        // In the mock, we return whatever bubble reasons provided.
        expect(res.reasonCodes).toContain(ReasonCode.UNTRUSTED_ISSUER);
    });

    test('DENY: Credential expired', async () => {
        const expiredCred: StoredCredentialMetadata = {
            ...validCred,
            id: 'expired-cred',
            expiresAt: new Date(Date.now() - 100000).toISOString() // Expired recently
        };
        const req: VerifierRequest = { verifierId: 'liquor-store-1', requestedClaims: ['isOver18'] };
        const res = await engine.evaluate(req, baseContext, [expiredCred], testPolicy);
        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.CREDENTIAL_EXPIRED);
    });

    test('PROMPT: Consent required logic', async () => {
        const req: VerifierRequest = { verifierId: 'sensitive-service', requestedClaims: ['health'] };
        const healthCred: StoredCredentialMetadata = { ...validCred, type: ['HealthCredential'], claims: ['health'] };

        const policyWithHealth = {
            ...testPolicy,
            trustedIssuers: [{ ...testPolicy.trustedIssuers[0], credentialTypes: ['AgeCredential', 'HealthCredential'] }]
        };

        const res = await engine.evaluate(req, baseContext, [healthCred], policyWithHealth);
        expect(res.verdict).toBe('PROMPT');
        expect(res.reasonCodes).toContain(ReasonCode.CONSENT_REQUIRED);
        expect(res.decisionCapsule).toBeDefined();
        expect(res.decisionCapsule?.verdict).toBe('PROMPT');
    });

    test('DENY: Unknown verifier', async () => {
        const req: VerifierRequest = { verifierId: 'random-hacker', requestedClaims: ['isOver18'] };
        const res = await engine.evaluate(req, baseContext, [validCred], testPolicy);
        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.UNKNOWN_VERIFIER);
    });
});
