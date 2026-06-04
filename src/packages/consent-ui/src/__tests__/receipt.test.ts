import { describe, expect, it } from 'vitest';
import { buildConsentReceipt } from '../receipt';
import type { ConsentRequest, ConsentResult } from '../types';

const req: ConsentRequest = {
    requestId: 'req-1',
    verifier: { id: 'did:askmi:verifier-x', displayName: 'X' },
    purpose: 'Age',
    claims: [
        { key: 'age', policyState: 'requested' },
        { key: 'name', policyState: 'denied' },
    ],
    predicates: [
        { id: 'pred_0_age_gte', claim: 'age', operation: 'gte', value: 18, policyState: 'allowed' },
    ],
    policy: { id: 'p1', version: '1.0.0', hash: 'sha256:abc' },
};

const result: ConsentResult = {
    requestId: 'req-1',
    verdict: 'CONSENTED',
    allowedClaims: ['age'],
    allowedPredicateIds: ['pred_0_age_gte'],
    withheldClaims: ['name'],
    withheldPredicateIds: [],
    timestamp: '2026-05-28T12:00:00.000Z',
};

describe('buildConsentReceipt', () => {
    it('produces a hash-linked receipt with no raw claim values', async () => {
        const r = await buildConsentReceipt(req, result);
        expect(r.requestId).toBe('req-1');
        expect(r.verdict).toBe('CONSENTED');
        expect(r.verifierRef.startsWith('sha256:')).toBe(true);
        expect(r.verifierRef).not.toContain('did:askmi:verifier-x');
        expect(r.requestHash).toMatch(/^[0-9a-f]{64}$/);
        expect(r.policyHash).toBe('sha256:abc');
        expect(r.allowedClaims).toEqual(['age']);
        expect(r.rawClaimsStored).toBe(false);
        expect(r.receiptId.startsWith('consent-')).toBe(true);
        // No raw value fields leak through:
        const serialized = JSON.stringify(r);
        expect(serialized).not.toContain('"raw"');
        expect(serialized).not.toContain('did:askmi:verifier-x');
    });

    it('is deterministic for the same inputs', async () => {
        const a = await buildConsentReceipt(req, result);
        const b = await buildConsentReceipt(req, result);
        expect(a.receiptId).toBe(b.receiptId);
        expect(a.requestHash).toBe(b.requestHash);
        expect(a.verifierRef).toBe(b.verifierRef);
    });

    it('rejects mismatched requestId between request and result', async () => {
        const bad: ConsentResult = { ...result, requestId: 'req-other' };
        await expect(buildConsentReceipt(req, bad)).rejects.toThrow(/requestId/);
    });

    it('sorts allowed/withheld arrays', async () => {
        const r = await buildConsentReceipt(req, {
            ...result,
            allowedClaims: ['z', 'a', 'm'],
            withheldClaims: ['c', 'b'],
        });
        expect(r.allowedClaims).toEqual(['a', 'm', 'z']);
        expect(r.withheldClaims).toEqual(['b', 'c']);
    });
});
