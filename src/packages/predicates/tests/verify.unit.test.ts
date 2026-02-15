import { describe, it, expect } from 'vitest';
import { CommonPredicates, evaluatePredicates, verifyPredicateResult, buildAllowedPredicateSet } from '../src/index';
import type { PredicateRequest } from '@mitch/shared-types';

describe('verifyPredicateResult (unit)', () => {
    const credential = {
        credentialSubject: {
            birthDate: '1995-06-15'
        }
    };

    const signFn = async (data: string) => `sig:${data.length}`;
    const verifyFn = async (data: string, sig: string) => sig === `sig:${data.length}`;

    it('fails closed if signature invalid', async () => {
        const pred = CommonPredicates.ageAtLeast(18);
        const allowed = await buildAllowedPredicateSet([pred]);

        const req: PredicateRequest = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-1',
            purpose: 'Age gate',
            timestamp: '2026-01-28T00:00:00.000Z',
            predicates: [pred]
        };

        const res = await evaluatePredicates(credential, req, async () => 'sig:bad');
        const out = await verifyPredicateResult(res, req, allowed, verifyFn);

        expect(out.valid).toBe(false);
        expect(out.errors.some(e => e.toLowerCase().includes('signature'))).toBe(true);
    });
});
