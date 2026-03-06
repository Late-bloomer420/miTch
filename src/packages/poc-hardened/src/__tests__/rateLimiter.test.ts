import { describe, it, expect, beforeEach } from 'vitest';
import { checkRateLimit, resetRateLimiter, type RateLimitConfig } from '../api/rateLimiter';

const CFG: RateLimitConfig = { windowSeconds: 60, maxRequestsPerRequester: 3 };

beforeEach(() => {
    resetRateLimiter();
});

describe('RateLimiter', () => {
    it('allows first request', () => {
        expect(checkRateLimit('user-a', CFG)).toBe(true);
    });

    it('allows up to max requests', () => {
        expect(checkRateLimit('user-b', CFG)).toBe(true);
        expect(checkRateLimit('user-b', CFG)).toBe(true);
        expect(checkRateLimit('user-b', CFG)).toBe(true);
    });

    it('blocks after exceeding max requests', () => {
        checkRateLimit('user-c', CFG);
        checkRateLimit('user-c', CFG);
        checkRateLimit('user-c', CFG);
        expect(checkRateLimit('user-c', CFG)).toBe(false);
    });

    it('different requesters have independent limits', () => {
        checkRateLimit('user-d', CFG);
        checkRateLimit('user-d', CFG);
        checkRateLimit('user-d', CFG);
        // user-d exhausted, but user-e is fresh
        expect(checkRateLimit('user-e', CFG)).toBe(true);
    });

    it('global budget blocks all when exceeded', () => {
        const cfgGlobal: RateLimitConfig = { windowSeconds: 60, maxRequestsPerRequester: 100, maxRequestsGlobal: 2 };
        checkRateLimit('g1', cfgGlobal);
        checkRateLimit('g2', cfgGlobal);
        // Global budget exhausted
        expect(checkRateLimit('g3', cfgGlobal)).toBe(false);
    });

    it('resetRateLimiter clears state', () => {
        checkRateLimit('user-f', CFG);
        checkRateLimit('user-f', CFG);
        checkRateLimit('user-f', CFG);
        resetRateLimiter();
        // After reset, should allow again
        expect(checkRateLimit('user-f', CFG)).toBe(true);
    });
});
