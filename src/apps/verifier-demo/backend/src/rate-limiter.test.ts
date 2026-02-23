import { describe, it, expect } from 'vitest';
import { FixedWindowRateLimiter } from './rate-limiter';

describe('FixedWindowRateLimiter', () => {
    it('allows up to maxRequests in the same window and blocks the next', () => {
        const rl = new FixedWindowRateLimiter(60_000, 10, { maxEntries: 1000, pruneIntervalMs: 1000 });
        const key = 'ip:1.2.3.4';
        const t0 = 1_000_000;

        for (let i = 0; i < 10; i++) {
            const r = rl.check(key, t0);
            expect(r.allowed).toBe(true);
        }

        const blocked = rl.check(key, t0);
        expect(blocked.allowed).toBe(false);
        expect(blocked.remaining).toBe(0);
        expect(blocked.resetInMs).toBeGreaterThan(0);
    });

    it('resets after windowMs', () => {
        const rl = new FixedWindowRateLimiter(60_000, 2);
        const key = 'ip:1.2.3.4';
        const t0 = 1_000_000;

        expect(rl.check(key, t0).allowed).toBe(true);
        expect(rl.check(key, t0).allowed).toBe(true);
        expect(rl.check(key, t0).allowed).toBe(false);

        const t1 = t0 + 60_000;
        expect(rl.check(key, t1).allowed).toBe(true);
    });

    it('bounds map size by maxEntries (evicts oldest after pruning)', () => {
        const rl = new FixedWindowRateLimiter(60_000, 1, { maxEntries: 5, pruneIntervalMs: 0 });
        const t0 = 1_000_000;

        for (let i = 0; i < 20; i++) {
            rl.check(`ip:${i}`, t0);
        }

        const r = rl.check('ip:0', t0);
        expect(r.allowed).toBe(true);
        expect(rl.size()).toBeLessThanOrEqual(5);
    });

    it('prunes expired entries', () => {
        const rl = new FixedWindowRateLimiter(1000, 1, { maxEntries: 100, pruneIntervalMs: 0 });
        const t0 = 1_000_000;

        rl.check('ip:a', t0);
        rl.check('ip:b', t0);

        rl.check('ip:c', t0 + 2000);

        expect(rl.check('ip:a', t0 + 2000).allowed).toBe(true);
        expect(rl.check('ip:b', t0 + 2000).allowed).toBe(true);
    });
});
