import { describe, test, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../src/engine';
import type { VerifierRequest, PolicyManifest, StoredCredentialMetadata } from '@mitch/shared-types';

const baseContext: EvaluationContext = {
    timestamp: Date.now(),
    userDID: 'did:example:holder',
};

const validCred: StoredCredentialMetadata = {
    id: 'cred-1',
    issuer: 'did:example:gov-issuer',
    type: ['AgeCredential'],
    issuedAt: new Date().toISOString(),
    claims: ['isOver18'],
};

/** Policy whose single matching rule binds disclosure to a set of purposes. */
function policyWithAllowedPurposes(allowedPurposes?: string[]): PolicyManifest {
    return {
        version: '1.0',
        trustedIssuers: [
            { did: 'did:example:gov-issuer', name: 'Gov ID', credentialTypes: ['AgeCredential'] },
        ],
        rules: [
            {
                id: 'rule-age',
                verifierPattern: 'liquor-store-*',
                allowedClaims: ['isOver18'],
                requiresTrustedIssuer: true,
                priority: 10,
                ...(allowedPurposes ? { allowedPurposes } : {}),
            },
        ],
    };
}

describe('Purpose-Binding (Contextual Integrity)', () => {
    const engine = new PolicyEngine();

    test('legacy: no opt-in leaves behavior unchanged (ALLOW, no PURPOSE_BOUND)', async () => {
        const req: VerifierRequest = { verifierId: 'liquor-store-1', requestedClaims: ['isOver18'] };
        const res = await engine.evaluate(req, baseContext, [validCred], policyWithAllowedPurposes());
        expect(res.verdict).toBe('ALLOW');
        expect(res.reasonCodes).not.toContain(ReasonCode.PURPOSE_BOUND);
    });

    test('rule.allowedPurposes + matching purpose → ALLOW and records PURPOSE_BOUND', async () => {
        const req: VerifierRequest = {
            verifierId: 'liquor-store-1',
            requestedClaims: ['isOver18'],
            purpose: 'age_verification',
        };
        const res = await engine.evaluate(
            req,
            baseContext,
            [validCred],
            policyWithAllowedPurposes(['age_verification'])
        );
        expect(res.verdict).toBe('ALLOW');
        expect(res.reasonCodes).toContain(ReasonCode.PURPOSE_BOUND);
    });

    test('rule.allowedPurposes + mismatched purpose → DENY PURPOSE_NOT_ALLOWED', async () => {
        const req: VerifierRequest = {
            verifierId: 'liquor-store-1',
            requestedClaims: ['isOver18'],
            purpose: 'marketing',
        };
        const res = await engine.evaluate(
            req,
            baseContext,
            [validCred],
            policyWithAllowedPurposes(['age_verification'])
        );
        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.PURPOSE_NOT_ALLOWED);
    });

    test('rule.allowedPurposes + absent purpose → DENY PURPOSE_REQUIRED (fail-closed)', async () => {
        const req: VerifierRequest = { verifierId: 'liquor-store-1', requestedClaims: ['isOver18'] };
        const res = await engine.evaluate(
            req,
            baseContext,
            [validCred],
            policyWithAllowedPurposes(['age_verification'])
        );
        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.PURPOSE_REQUIRED);
    });

    test('falls back to usagePurpose when purpose is absent', async () => {
        const req: VerifierRequest = {
            verifierId: 'liquor-store-1',
            requestedClaims: ['isOver18'],
            usagePurpose: 'researchSecondary',
        };
        const res = await engine.evaluate(
            req,
            baseContext,
            [validCred],
            policyWithAllowedPurposes(['researchSecondary'])
        );
        expect(res.verdict).toBe('ALLOW');
        expect(res.reasonCodes).toContain(ReasonCode.PURPOSE_BOUND);
    });

    test('globalSettings.requirePurposeBinding denies a rule that declares no allowedPurposes', async () => {
        const policy = policyWithAllowedPurposes();
        policy.globalSettings = { requirePurposeBinding: true };
        const req: VerifierRequest = {
            verifierId: 'liquor-store-1',
            requestedClaims: ['isOver18'],
            purpose: 'age_verification',
        };
        const res = await engine.evaluate(req, baseContext, [validCred], policy);
        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.PURPOSE_NOT_ALLOWED);
    });
});
