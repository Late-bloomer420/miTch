import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';

vi.mock('@mitch/verifier-sdk', () => ({
    VerifierSDK: class {
        async verifyPresentation() {
            return {
                vp: {
                    presentations: [{ proven_claims: { 'age >= 18': true } }],
                    metadata: { issuer_trust_refs: ['did:example:issuer'] }
                },
                proof: { public_key_alg: 'mock' }
            };
        }
    }
}));

beforeEach(() => {
    vi.resetModules();
    process.env.MITCH_TEST_MODE = '1';
    delete process.env.TRUST_PROXY;
    delete process.env.TRUST_PROXY_HOPS;
});

describe('POST /present rate-limit headers', () => {
    it('returns 429 with coherent Retry-After and reset headers', async () => {
        const { app } = await import('./app');
        const agent = request(app);

        for (let i = 0; i < 10; i++) {
            await agent.post('/present').send({}).expect(200);
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
});
