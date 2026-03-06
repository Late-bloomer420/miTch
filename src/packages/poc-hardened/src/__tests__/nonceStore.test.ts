import { describe, it, expect } from 'vitest';
import { InMemoryNonceStore } from '../binding/nonceStore';
import { isExpired } from '../binding/expiryValidator';

describe('InMemoryNonceStore', () => {
    it('first use returns ok', async () => {
        const store = new InMemoryNonceStore();
        expect(await store.consumeOnce('aud1', 'nonce-1', 60)).toBe('ok');
    });

    it('second use of same nonce returns replay', async () => {
        const store = new InMemoryNonceStore();
        await store.consumeOnce('aud1', 'nonce-2', 60);
        expect(await store.consumeOnce('aud1', 'nonce-2', 60)).toBe('replay');
    });

    it('same nonce for different audiences is ok', async () => {
        const store = new InMemoryNonceStore();
        await store.consumeOnce('aud1', 'shared-nonce', 60);
        expect(await store.consumeOnce('aud2', 'shared-nonce', 60)).toBe('ok');
    });

    it('expired nonce can be reused', async () => {
        const store = new InMemoryNonceStore();
        await store.consumeOnce('aud1', 'nonce-exp', 0); // TTL = 0 seconds
        // Wait a tiny bit
        await new Promise(r => setTimeout(r, 10));
        expect(await store.consumeOnce('aud1', 'nonce-exp', 60)).toBe('ok');
    });
});

describe('isExpired', () => {
    it('returns false for future timestamp', () => {
        const future = new Date(Date.now() + 3600_000).toISOString();
        expect(isExpired(future)).toBe(false);
    });

    it('returns true for past timestamp', () => {
        const past = new Date(Date.now() - 3600_000).toISOString();
        expect(isExpired(past)).toBe(true);
    });

    it('returns true for invalid date string', () => {
        expect(isExpired('not-a-date')).toBe(true);
    });

    it('respects skew window (90s by default)', () => {
        // 60 seconds in the past — within 90s skew, should NOT be expired
        const recent = new Date(Date.now() - 60_000).toISOString();
        expect(isExpired(recent)).toBe(false);
    });

    it('expired outside skew', () => {
        const old = new Date(Date.now() - 120_000).toISOString(); // 120s ago > 90s skew
        expect(isExpired(old)).toBe(true);
    });
});
