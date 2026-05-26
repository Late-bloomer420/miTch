import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EUDITrustListResolver, TrustList } from './trust-list-resolver';

describe('EUDITrustListResolver', () => {
    let resolver: EUDITrustListResolver;
    const mockTsl: TrustList = {
        id: 'test-tsl',
        version: '1.0',
        validUntil: '2030-01-01',
        issuers: ['did:example:trusted-issuer'],
        verifiers: ['did:example:trusted-verifier']
    };

    beforeEach(() => {
        resolver = new EUDITrustListResolver();
    });

    it('should resolve a trusted issuer from the TSL', async () => {
        const fetchFn = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockTsl
        });
        resolver.setFetch(fetchFn as any);

        const result = await resolver.isIssuerTrusted('did:example:trusted-issuer');

        expect(result.isTrusted).toBe(true);
        expect(result.decision).toBe('ALLOW');
        expect(result.fromCache).toBe(false);
    });

    it('should deny an untrusted issuer', async () => {
        const fetchFn = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockTsl
        });
        resolver.setFetch(fetchFn as any);

        const result = await resolver.isIssuerTrusted('did:example:evil-issuer');

        expect(result.isTrusted).toBe(false);
        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('ENTITY_NOT_IN_TSL');
    });

    it('should resolve a trusted verifier', async () => {
        const fetchFn = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockTsl
        });
        resolver.setFetch(fetchFn as any);

        const result = await resolver.isVerifierTrusted('did:example:trusted-verifier');

        expect(result.isTrusted).toBe(true);
    });

    it('should handle fetch failures with fail-closed (high risk)', async () => {
        const fetchFn = vi.fn().mockRejectedValue(new Error('Network error'));
        resolver.setFetch(fetchFn as any);

        const result = await resolver.isIssuerTrusted('did:example:trusted-issuer', 'high');

        expect(result.isTrusted).toBe(false);
        expect(result.decision).toBe('DENY');
        expect(result.reason).toContain('TRUST_SOURCE_UNAVAILABLE');
    });

    it('should use cache if fetch fails but cache is fresh', async () => {
        // First successful fetch
        const fetchFnSuccess = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockTsl
        });
        resolver.setFetch(fetchFnSuccess as any);
        await resolver.isIssuerTrusted('did:example:trusted-issuer');

        // Second failed fetch
        const fetchFnFail = vi.fn().mockRejectedValue(new Error('Network error'));
        resolver.setFetch(fetchFnFail as any);

        const result = await resolver.isIssuerTrusted('did:example:trusted-issuer', 'high');

        expect(result.isTrusted).toBe(true);
        expect(result.fromCache).toBe(true);
    });

    it('should use cache during grace period (low risk)', async () => {
        // Setup stale cache manually or via mock time
        const fetchFnSuccess = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockTsl
        });
        resolver.setFetch(fetchFnSuccess as any);

        // We need to control time for cache expiry
        vi.useFakeTimers();
        await resolver.isIssuerTrusted('did:example:trusted-issuer');

        // Advance time beyond cache TTL but within grace period
        vi.advanceTimersByTime(25 * 60 * 60 * 1000); // 25 hours (TTL is 24)

        const fetchFnFail = vi.fn().mockRejectedValue(new Error('Network error'));
        resolver.setFetch(fetchFnFail as any);

        const result = await resolver.isIssuerTrusted('did:example:trusted-issuer', 'low');

        expect(result.isTrusted).toBe(true);
        expect(result.fromCache).toBe(true);

        vi.useRealTimers();
    });
});
