import { describe, it, expect } from 'vitest';
import { evaluatePredicates, CommonPredicates, hashRequestAsync } from '../src/index';
import type { PredicateRequest } from '../src/canonical';

describe('evaluatePredicates (unit)', () => {
    const credential = {
        credentialSubject: {
            birthDate: '1995-06-15',
            residency: 'DE',
            creditScore: 720
        }
    };

    const signFn = async (data: string) => `sig:${data.length}`;

    it('fails closed on missing path', async () => {
        const req: PredicateRequest = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-1',
            purpose: 'Age gate',
            timestamp: '2026-01-28T00:00:00.000Z',
            predicates: [{
                id: 'missing',
                description: 'Missing path',
                credentialTypes: ['X'],
                expression: {
                    logic: 'and',
                    clauses: [{ path: 'credentialSubject.nope', op: 'exists', value: true, type: 'boolean' }]
                }
            }]
        };

        const res = await evaluatePredicates(credential, req, signFn);
        expect(res.proof.allPassed).toBe(false);
        expect(res.proof.evaluations[0].reasonCode).toBe('MISSING_PATH');
    });

    it('binding.requestHash matches hashRequestAsync(request)', async () => {
        const req: PredicateRequest = {
            verifierDid: 'did:web:shop.example',
            nonce: 'n-2',
            purpose: 'Age gate',
            timestamp: '2026-01-28T00:00:00.000Z',
            predicates: [CommonPredicates.ageAtLeast(18)]
        };

        const res = await evaluatePredicates(credential, req, signFn);
        expect(res.proof.binding.requestHash).toBe(await hashRequestAsync(req));
    });
});
