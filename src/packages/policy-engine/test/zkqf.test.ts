
import { describe, test, expect } from 'vitest';
import { PolicyEngine, ReasonCode, EvaluationContext } from '../src/engine';
import type { VerifierRequest, PolicyManifest, StoredCredentialMetadata } from '@mitch/shared-types';

const baseContext: EvaluationContext = {
    timestamp: Date.now(),
    userDID: 'did:example:holder',
};

const zkPolicy: PolicyManifest = {
    version: '2.0',
    trustedIssuers: [
        {
            did: 'did:example:gov-issuer',
            name: 'Gov ID',
            credentialTypes: ['AgeCredential']
        }
    ],
    rules: [
        {
            id: 'rule-minimized',
            verifierPattern: 'minimizer-service',
            allowedClaims: ['isOver18'], // Only allow age check
            // deniedClaims: [] -> 'address' is implicity clipped
            requiresTrustedIssuer: true,
            priority: 10
        },
        {
            id: 'rule-explicit-deny',
            verifierPattern: 'denier-service',
            allowedClaims: ['isOver18'],
            deniedClaims: ['ssn'], // Explicitly denied
            requiresTrustedIssuer: true,
            priority: 10
        }
    ],
    globalSettings: {
        blockUnknownVerifiers: true
    }
};

const richCred: StoredCredentialMetadata = {
    id: 'cred-rich',
    issuer: 'did:example:gov-issuer',
    type: ['AgeCredential'],
    issuedAt: new Date().toISOString(),
    claims: ['isOver18', 'address', 'ssn', 'name']
};

describe('ZKQF - Zero-Knowledge Query Firewall', () => {
    const engine = new PolicyEngine();

    test('T-34a: Output is clipped to intersection of Requested & Allowed', async () => {
        // Request asks for Allowed(isOver18) + Unallowed(address)
        const req: VerifierRequest = {
            verifierId: 'minimizer-service',
            requestedClaims: ['isOver18', 'address']
        };

        const res = await engine.evaluate(req, baseContext, [richCred], zkPolicy);

        // Expect ALLOW (because we have isOver18)
        expect(res.verdict).toBe('ALLOW');

        // Check Bounded Disclosure
        const capsule = res.decisionCapsule!;
        expect(capsule.allowed_claims).toContain('isOver18');
        expect(capsule.allowed_claims).not.toContain('address');
        expect(capsule.allowed_claims).toHaveLength(1);
    });

    test('T-34a: Fail-closed if Explicitly Denied claim is requested', async () => {
        const req: VerifierRequest = {
            verifierId: 'denier-service',
            requestedClaims: ['isOver18', 'ssn']
        };

        const res = await engine.evaluate(req, baseContext, [richCred], zkPolicy);

        expect(res.verdict).toBe('DENY');
        expect(res.reasonCodes).toContain(ReasonCode.CLAIM_NOT_ALLOWED);
    });

    test('T-34a: Fail-closed if intersection is empty', async () => {
        // Request only things that are not allowed (but not explicitly denied)
        const req: VerifierRequest = {
            verifierId: 'minimizer-service',
            requestedClaims: ['address', 'name']
        };

        const res = await engine.evaluate(req, baseContext, [richCred], zkPolicy);

        expect(res.verdict).toBe('DENY');
        // Reason could be CLAIM_NOT_ALLOWED or NO_SUITABLE_CREDENTIAL depending on implementation,
        // but since we return early if intersection empty:
        expect(res.reasonCodes).toContain(ReasonCode.CLAIM_NOT_ALLOWED);
    });

    test('T-34a: Minimization applies to Credential Selection', async () => {
        // We have a credential that HAS 'isOver18' BUT NOT 'address'.
        // Request asks for ['isOver18', 'address'].
        // Policy only allows 'isOver18'.
        // Logic: Intersection = ['isOver18'].
        // Credential has ['isOver18'].
        // Therefore, this credential SHOULD be suitable. (Previous logic would reject it because it lacks 'address')

        const minimalCred: StoredCredentialMetadata = {
            id: 'cred-min',
            issuer: 'did:example:gov-issuer',
            type: ['AgeCredential'],
            issuedAt: new Date().toISOString(),
            claims: ['isOver18'] // Does NOT have address
        };

        const req: VerifierRequest = {
            verifierId: 'minimizer-service',
            requestedClaims: ['isOver18', 'address']
        };

        const res = await engine.evaluate(req, baseContext, [minimalCred], zkPolicy);

        expect(res.verdict).toBe('ALLOW');
        expect(res.selectedCredentials).toContain('cred-min');
        expect(res.decisionCapsule?.allowed_claims).toEqual(['isOver18']);
    });
});
