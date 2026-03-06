/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from 'vitest';
import {
    MultiSourceStatusResolver,
    decodeStatusListBitstring,
    checkBitstringIndex,
    encodeStatusListBitstring,
    extractRevokedIndices,
} from '../multi-source';
import type { StatusListEntry } from '../types';

// ─── Helpers ──────────────────────────────────────────────────────

function makeEntry(url: string, index: string = '0'): StatusListEntry {
    return {
        id: `${url}#${index}`,
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: index,
        statusListCredential: url,
    };
}

// ─── Bitstring Tests (Spec 68) ─────────────────────────────────────

describe('StatusList2021 Bitstring (Spec 68)', () => {
    it('encodes and decodes bitstring round-trip', () => {
        const encoded = encodeStatusListBitstring(16, [0, 5, 15]);
        const decoded = decodeStatusListBitstring(encoded);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded.length).toBe(2); // 16 bits = 2 bytes
    });

    it('checkBitstringIndex finds revoked indices', () => {
        const encoded = encodeStatusListBitstring(16, [3, 7]);
        const bits = decodeStatusListBitstring(encoded);
        expect(checkBitstringIndex(bits, 3)).toBe(true);
        expect(checkBitstringIndex(bits, 7)).toBe(true);
        expect(checkBitstringIndex(bits, 0)).toBe(false);
        expect(checkBitstringIndex(bits, 5)).toBe(false);
    });

    it('throws RangeError for out-of-bounds index', () => {
        const bits = new Uint8Array(1); // 8 bits
        expect(() => checkBitstringIndex(bits, 8)).toThrow(RangeError);
        expect(() => checkBitstringIndex(bits, -1)).toThrow(RangeError);
    });

    it('MSB-first: index 0 = most significant bit of byte 0', () => {
        // Set bit 0 (MSB): byte 0 = 0b10000000 = 128
        const bits = new Uint8Array([0b10000000]);
        expect(checkBitstringIndex(bits, 0)).toBe(true);
        expect(checkBitstringIndex(bits, 1)).toBe(false);
    });

    it('extractRevokedIndices returns all set indices', () => {
        const encoded = encodeStatusListBitstring(32, [0, 1, 15, 31]);
        const bits = decodeStatusListBitstring(encoded);
        const revoked = extractRevokedIndices(bits);
        expect(revoked).toContain(0);
        expect(revoked).toContain(1);
        expect(revoked).toContain(15);
        expect(revoked).toContain(31);
        expect(revoked).toHaveLength(4);
    });

    it('empty bitstring has no revoked indices', () => {
        const encoded = encodeStatusListBitstring(16, []);
        const bits = decodeStatusListBitstring(encoded);
        expect(extractRevokedIndices(bits)).toHaveLength(0);
    });
});

// ─── Multi-Source Resolver Tests (Spec 62) ─────────────────────────

describe('MultiSourceStatusResolver (Spec 62)', () => {
    it('falls back to secondary URL on primary failure', async () => {
        const failFetch = async () => { throw new Error('Network error'); };
        const okFetch = async (url: string) => {
            const encoded = encodeStatusListBitstring(16, []);
            return {
                ok: true,
                json: async () => ({
                    '@context': [],
                    id: url,
                    type: ['VerifiableCredential', 'StatusList2021Credential'],
                    issuer: 'did:example:issuer',
                    issuanceDate: new Date().toISOString(),
                    credentialSubject: {
                        id: `${url}#list`,
                        type: 'StatusList2021',
                        statusPurpose: 'revocation',
                        encodedList: encoded,
                    },
                }),
            } as Response;
        };

        let callCount = 0;
        const mockFetch = async (url: string, _init?: RequestInit) => {
            callCount++;
            if (callCount === 1) return failFetch() as any;
            return okFetch(url) as any;
        };

        const resolver = new MultiSourceStatusResolver({ fetchFn: mockFetch as typeof fetch });
        const entry = makeEntry('https://primary.example.com/status', '0');
        const result = await resolver.resolve(entry, ['https://fallback.example.com/status'], 'low');

        // With high risk tier, primary fail = DENY even with fallback
        // With low risk tier, can use fallback
        expect(result.attemptedSources).toContain('https://primary.example.com/status');
    });

    it('all sources fail → DENY with ALL_SOURCES_UNAVAILABLE', async () => {
        const failFetch = async () => { throw new Error('All fail'); };
        const resolver = new MultiSourceStatusResolver({ fetchFn: failFetch as any });
        const entry = makeEntry('https://primary.example.com/status');
        const result = await resolver.resolve(entry, ['https://fallback.example.com/status'], 'high');

        expect(result.decision).toBe('DENY');
        expect(result.reason).toBe('ALL_SOURCES_UNAVAILABLE');
        expect(result.attemptedSources).toHaveLength(2);
    });

    it('resolves DENY for revoked credential', async () => {
        const encoded = encodeStatusListBitstring(16, [5]); // index 5 is revoked
        const mockFetch = async (url: string) => ({
            ok: true,
            json: async () => ({
                '@context': [],
                id: url,
                type: ['VerifiableCredential', 'StatusList2021Credential'],
                issuer: 'did:example:issuer',
                issuanceDate: new Date().toISOString(),
                credentialSubject: {
                    id: `${url}#list`,
                    type: 'StatusList2021',
                    statusPurpose: 'revocation',
                    encodedList: encoded,
                },
            }),
        }) as Response;

        const resolver = new MultiSourceStatusResolver({ fetchFn: mockFetch as any });
        const entry = makeEntry('https://status.example.com/list', '5');
        const result = await resolver.resolve(entry, [], 'high');

        expect(result.decision).toBe('DENY');
        expect(result.revoked).toBe(true);
        expect(result.fallbackUsed).toBe(false);
    });

    it('clears all caches', () => {
        const resolver = new MultiSourceStatusResolver();
        resolver.clearAllCaches();
        expect(resolver.sourceCount).toBe(0);
    });

    it('batch resolve handles multiple entries', async () => {
        const failFetch = async () => { throw new Error('fail'); };
        const resolver = new MultiSourceStatusResolver({ fetchFn: failFetch as any });
        const results = await resolver.resolveBatch([
            { entry: makeEntry('https://a.example.com/s1', '0'), riskTier: 'high' },
            { entry: makeEntry('https://b.example.com/s2', '1'), riskTier: 'high' },
        ]);
        expect(results).toHaveLength(2);
        expect(results.every(r => r.decision === 'DENY')).toBe(true);
    });
});
