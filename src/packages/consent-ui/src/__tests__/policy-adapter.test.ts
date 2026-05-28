import { describe, expect, it } from 'vitest';
import { fromPolicyDecision } from '../policy-adapter';
import type { Decision, DisclosureRequest } from '@mitch/policy-engine';

const baseRequest: DisclosureRequest = {
    requestId: 'req-1',
    verifierDid: 'did:mitch:verifier-liquor-store',
    purpose: 'Age Verification',
    requestedClaims: ['age', 'name'],
    requestedPredicates: [
        { claim: 'age', operation: 'gte', value: 18 },
        { claim: 'address', operation: 'eq', value: 'AT' },
    ],
};

describe('fromPolicyDecision', () => {
    it('marks raw claims as requested when no decision is supplied', () => {
        const cr = fromPolicyDecision({ request: baseRequest });
        expect(cr.requestId).toBe('req-1');
        expect(cr.claims.map((c) => [c.key, c.policyState])).toEqual([
            ['age', 'requested'],
            ['name', 'requested'],
        ]);
        expect(cr.predicates.every((p) => p.policyState === 'requested')).toBe(true);
    });

    it('marks denied claims and predicates as denied per decision.deniedClaims', () => {
        const decision: Decision = {
            verdict: 'PROMPT',
            responseMode: 'PREDICATE_PROOF',
            policyId: 'p1',
            requestId: 'req-1',
            deniedClaims: ['name', 'address'],
            reasonCodes: [],
            rawClaimsDisclosed: false,
        };
        const cr = fromPolicyDecision({ request: baseRequest, decision });
        expect(cr.claims.find((c) => c.key === 'name')?.policyState).toBe('denied');
        expect(cr.claims.find((c) => c.key === 'age')?.policyState).toBe('requested');
        expect(cr.predicates.find((p) => p.claim === 'address')?.policyState).toBe('denied');
    });

    it('marks the predicate matching decision.allowedDisclosure as allowed', () => {
        const decision: Decision = {
            verdict: 'ALLOW',
            responseMode: 'PREDICATE_PROOF',
            policyId: 'p1',
            requestId: 'req-1',
            allowedDisclosure: { type: 'predicate', claim: 'age', operation: 'gte', value: 18 },
            deniedClaims: [],
            reasonCodes: [],
            rawClaimsDisclosed: false,
        };
        const cr = fromPolicyDecision({ request: baseRequest, decision });
        const agePred = cr.predicates.find((p) => p.claim === 'age');
        expect(agePred?.policyState).toBe('allowed');
        const addrPred = cr.predicates.find((p) => p.claim === 'address');
        expect(addrPred?.policyState).toBe('requested');
    });

    it('carries policy reference and previews/labels', () => {
        const cr = fromPolicyDecision({
            request: baseRequest,
            policy: { id: 'p1', version: '1.0.0', hash: 'sha256:abc' },
            verifierDisplayName: "Joe's Liquor Store",
            previews: { age: '18+' },
            labels: { age: 'Age', name: 'Full name' },
        });
        expect(cr.verifier.displayName).toBe("Joe's Liquor Store");
        expect(cr.policy).toEqual({ id: 'p1', version: '1.0.0', hash: 'sha256:abc' });
        expect(cr.claims.find((c) => c.key === 'age')?.preview).toBe('18+');
        expect(cr.claims.find((c) => c.key === 'age')?.label).toBe('Age');
    });
});
