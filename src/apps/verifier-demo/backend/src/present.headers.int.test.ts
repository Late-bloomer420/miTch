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
    it('returns 429 with coherent Retry-After and reset headers', { timeout: 30_000 }, async () => {
        const { app } = await import('./app');
        const agent = request(app);

        // Fail-closed: these carry only a legacy boolean (no ZK proof), so each is 403 —
        // but still counts toward the rate limit, so the 31st is rate-limited.
        for (let i = 0; i < 30; i++) {
            await agent.post('/present').send({}).expect(403);
        }

        const res = await agent.post('/present').send({}).expect(429);

        const retryAfter = Number(res.header['retry-after']);
        const resetSeconds = Number(res.header['ratelimit-reset']);

        // Standard express-rate-limit headers with standardHeaders: true
        expect(Number.isFinite(retryAfter)).toBe(true);
        expect(Number.isFinite(resetSeconds)).toBe(true);

        expect(retryAfter).toBeGreaterThan(0);
        expect(resetSeconds).toBeGreaterThan(0);
    });

    it('fails closed: rejects a legacy boolean proven_claims without a ZK proof', async () => {
        const { app } = await import('./app');
        const res = await request(app).post('/present').send({}).expect(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toBe('AGE_NOT_VERIFIED');
    });
});
