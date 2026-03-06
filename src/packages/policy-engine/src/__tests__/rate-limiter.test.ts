import { describe, it, expect } from 'vitest';
import { PolicyRateLimiter } from '../rate-limiter';

describe('PolicyRateLimiter', () => {
    it('allows first request', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 5, windowMs: 60_000 });
        const r = limiter.check('verifier1', 'user1');
        expect(r.allowed).toBe(true);
    });

    it('blocks when verifier limit exceeded', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 3, windowMs: 60_000 });
        limiter.check('v1', 'u1');
        limiter.check('v1', 'u2');
        limiter.check('v1', 'u3');
        const r = limiter.check('v1', 'u4');
        expect(r.allowed).toBe(false);
        expect(r.reason).toContain('RATE_LIMIT_VERIFIER');
    });

    it('blocks when user limit exceeded', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 100, windowMs: 60_000, perUserMaxRequests: 2 });
        limiter.check('v1', 'alice');
        limiter.check('v2', 'alice');
        const r = limiter.check('v3', 'alice');
        expect(r.allowed).toBe(false);
        expect(r.reason).toContain('RATE_LIMIT_USER');
    });

    it('different verifiers have independent limits', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 2, windowMs: 60_000 });
        limiter.check('v1', 'u1');
        limiter.check('v1', 'u2');
        const r = limiter.checkVerifier('v2');
        expect(r.allowed).toBe(true);
    });

    it('resetVerifier clears limit', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 2, windowMs: 60_000 });
        limiter.checkVerifier('v1');
        limiter.checkVerifier('v1');
        limiter.resetVerifier('v1');
        const r = limiter.checkVerifier('v1');
        expect(r.allowed).toBe(true);
    });

    it('provides remaining count', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 5, windowMs: 60_000 });
        limiter.check('v1', 'u1');
        limiter.check('v1', 'u2');
        const r = limiter.check('v1', 'u3');
        expect(r.remaining).toBe(2); // 5 slots, 3 used (2 before + 1 now)
    });

    it('getVerifierCount reflects current window', () => {
        const limiter = new PolicyRateLimiter({ maxRequests: 10, windowMs: 60_000 });
        limiter.checkVerifier('v1');
        limiter.checkVerifier('v1');
        expect(limiter.getVerifierCount('v1')).toBe(2);
    });
});
