import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import { CommonPredicates, evaluatePredicates } from '@askmi/predicates';
import { signData } from '@askmi/shared-crypto';

const mocks = vi.hoisted(() => ({
    verifierResult: {
        vp: {
            presentations: [{ proven_claims: { 'age >= 18': true } }],
            metadata: { issuer_trust_refs: ['did:example:issuer'] }
        },
        proof: { public_key_alg: 'mock' }
    } as {
        vp: {
            presentations: Array<Record<string, unknown>>;
            metadata: Record<string, unknown>;
        };
        proof: Record<string, unknown>;
    }
}));

vi.mock('@askmi/verifier-sdk', () => ({
    VerifierSDK: class {
        async verifyPresentation() {
            return mocks.verifierResult;
        }
    }
}));

beforeEach(() => {
    vi.resetModules();
    process.env.ASKMI_TEST_MODE = '1';
    delete process.env.TRUST_PROXY;
    delete process.env.TRUST_PROXY_HOPS;
    mocks.verifierResult.vp = {
        presentations: [{ proven_claims: { 'age >= 18': true } }],
        metadata: { issuer_trust_refs: ['did:example:issuer'] }
    };
});

describe('POST /present rate-limit headers', () => {
    it('returns 429 with coherent Retry-After and reset headers', { timeout: 30_000 }, async () => {
        const { app } = await import('./app');
        const agent = request(app);

        // Fail-closed: these carry only a legacy boolean (no ZK proof), so each is 403 —
        // but still counts toward the rate limit, so the 11th is rate-limited.
        for (let i = 0; i < 10; i++) {
            await agent.post('/present').send({}).expect(403);
        }

        const res = await agent.post('/present').send({}).expect(429);

        const retryAfter = Number(res.header['retry-after']);
        const resetAfter = Number(res.header['x-ratelimit-reset-after']);
        const resetEpoch = Number(res.header['x-ratelimit-reset']);

        expect(Number.isFinite(retryAfter)).toBe(true);
        expect(retryAfter).toBe(resetAfter);

        const nowEpoch = Math.floor(Date.now() / 1000);
        expect(resetEpoch).toBeGreaterThanOrEqual(nowEpoch);
        expect(resetEpoch).toBeLessThanOrEqual(nowEpoch + resetAfter + 1);
    });

    it('fails closed: rejects a legacy boolean proven_claims without a ZK proof', async () => {
        const { app } = await import('./app');
        const res = await request(app).post('/present').send({}).expect(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe('AGE_NOT_VERIFIED');
    });

    it('accepts a current PredicateResult proof with nested proof.binding', async () => {
        const proofKeys = await globalThis.crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        );
        const publicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', proofKeys.publicKey);
        const predicateRequest = {
            verifierDid: 'did:askmi:verifier-liquor-store',
            nonce: 'nonce-current-predicate-shape',
            purpose: 'Age Verification',
            timestamp: new Date().toISOString(),
            predicates: [CommonPredicates.ageAtLeast(18)]
        };
        const predicateResult = await evaluatePredicates(
            { credentialSubject: { dateOfBirth: '2000-01-01' } },
            predicateRequest,
            (data) => signData(data, proofKeys.privateKey)
        );

        mocks.verifierResult.vp = {
            presentations: [
                {
                    zkp_proofs: {
                        'age >= 18': {
                            ...predicateResult,
                            publicKeyJwk
                        }
                    }
                }
            ],
            metadata: { issuer_trust_refs: ['did:example:issuer'] }
        };

        const { app } = await import('./app');
        const res = await request(app).post('/present').send({}).expect(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.message).toContain('Welcome!');
    });
});
