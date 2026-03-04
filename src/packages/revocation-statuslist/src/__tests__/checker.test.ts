import { describe, it, expect, beforeEach, vi } from 'vitest';
import { StatusListRevocationChecker } from '../index';
import type { StatusListEntry, StatusListCredential } from '../types';

// ─── Test Helpers ─────────────────────────────────────────────────────────

function makeEncodedList(revokedIndices: number[], byteCount = 4): string {
  const bytes = new Uint8Array(byteCount);
  for (const idx of revokedIndices) {
    const byteIndex = Math.floor(idx / 8);
    const bitIndex = idx % 8;
    if (byteIndex < byteCount) {
      bytes[byteIndex] |= 1 << (7 - bitIndex); // MSB-first per spec
    }
  }
  return btoa(String.fromCharCode(...bytes));
}

function makeCredential(
  revokedIndices: number[],
  purpose: 'revocation' | 'suspension' = 'revocation',
): StatusListCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'https://example.com/status-list/1',
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: 'did:example:issuer',
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'https://example.com/status-list/1#list',
      type: 'StatusList2021',
      statusPurpose: purpose,
      encodedList: makeEncodedList(revokedIndices),
    },
  };
}

function makeEntry(index: number, url = 'https://example.com/status-list/1'): StatusListEntry {
  return {
    id: `${url}#${index}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential: url,
  };
}

function mockFetchOk(credential: StatusListCredential): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(credential),
  }) as any;
}

function mockFetchFail(): typeof fetch {
  return vi.fn().mockRejectedValue(new Error('Network error')) as any;
}

function mockFetchTimeout(): typeof fetch {
  return vi.fn().mockImplementation(() => new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Aborted')), 50);
  })) as any;
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe('StatusListRevocationChecker', () => {
  const credential = makeCredential([5, 10]); // indices 5 and 10 are revoked

  describe('valid credential (not revoked) → ALLOW', () => {
    it('returns ALLOW for non-revoked index', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchOk(credential),
      });

      const result = await checker.checkRevocation(makeEntry(0));
      expect(result.decision).toBe('ALLOW');
      expect(result.revoked).toBe(false);
      expect(result.denyCode).toBeUndefined();
    });

    it('returns ALLOW for index 3 (not in revoked set)', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchOk(credential),
      });

      const result = await checker.checkRevocation(makeEntry(3));
      expect(result.decision).toBe('ALLOW');
      expect(result.revoked).toBe(false);
    });
  });

  describe('revoked credential → DENY', () => {
    it('returns DENY with REVOKED reason for revoked index', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchOk(credential),
      });

      const result = await checker.checkRevocation(makeEntry(5));
      expect(result.decision).toBe('DENY');
      expect(result.revoked).toBe(true);
      expect(result.reason).toBe('REVOKED');
      expect(result.denyCode).toBe('DENY_CREDENTIAL_REVOKED');
    });

    it('returns DENY for another revoked index', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchOk(credential),
      });

      const result = await checker.checkRevocation(makeEntry(10));
      expect(result.decision).toBe('DENY');
      expect(result.revoked).toBe(true);
    });
  });

  describe('status server unreachable → DENY (fail-closed)', () => {
    it('returns DENY with STATUS_SOURCE_UNAVAILABLE for high-risk', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchFail(),
      });

      const result = await checker.checkRevocation(makeEntry(0), 'high');
      expect(result.decision).toBe('DENY');
      expect(result.revoked).toBe(false);
      expect(result.reason).toBe('STATUS_SOURCE_UNAVAILABLE');
      expect(result.denyCode).toBe('DENY_STATUS_SOURCE_UNAVAILABLE');
    });

    it('returns DENY on timeout for high-risk', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchTimeout(),
        fetchTimeoutMs: 10,
      });

      const result = await checker.checkRevocation(makeEntry(0), 'high');
      expect(result.decision).toBe('DENY');
      expect(result.denyCode).toBe('DENY_STATUS_SOURCE_UNAVAILABLE');
    });
  });

  describe('cache behavior', () => {
    it('uses cached status list when fresh', async () => {
      const fetchFn = mockFetchOk(credential);
      const checker = new StatusListRevocationChecker({
        fetchFn,
        cacheTtlMs: 60_000,
      });

      // First call — fetches
      await checker.checkRevocation(makeEntry(0));
      expect(fetchFn).toHaveBeenCalledTimes(1);

      // Second call — from cache
      const result = await checker.checkRevocation(makeEntry(0));
      expect(fetchFn).toHaveBeenCalledTimes(1); // No additional fetch
      expect(result.fromCache).toBe(true);
      expect(result.decision).toBe('ALLOW');
    });

    it('re-fetches when cache expires', async () => {
      const fetchFn = mockFetchOk(credential);
      const checker = new StatusListRevocationChecker({
        fetchFn,
        cacheTtlMs: 1, // 1ms TTL — expires immediately
      });

      await checker.checkRevocation(makeEntry(0));
      expect(fetchFn).toHaveBeenCalledTimes(1);

      // Wait for cache to expire
      await new Promise(r => setTimeout(r, 10));

      await checker.checkRevocation(makeEntry(0));
      expect(fetchFn).toHaveBeenCalledTimes(2); // Re-fetched
    });
  });

  describe('offline grace period', () => {
    it('low-risk: uses stale cache within grace period', async () => {
      const fetchFn = mockFetchOk(credential);
      const checker = new StatusListRevocationChecker({
        fetchFn,
        cacheTtlMs: 1, // Expires immediately
        offlineGraceMsLowRisk: 60_000, // 1 min grace
      });

      // Prime cache
      await checker.checkRevocation(makeEntry(0), 'low');
      expect(fetchFn).toHaveBeenCalledTimes(1);

      // Wait for cache to expire
      await new Promise(r => setTimeout(r, 10));

      // Now make fetch fail
      (fetchFn as any).mockRejectedValue(new Error('offline'));

      // Should use stale cache within grace period
      const result = await checker.checkRevocation(makeEntry(0), 'low');
      expect(result.decision).toBe('ALLOW');
      expect(result.fromCache).toBe(true);
      expect(result.graceMode).toBe(true);
    });

    it('low-risk: DENY beyond grace period', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchFail(),
        cacheTtlMs: 1,
        offlineGraceMsLowRisk: 1, // 1ms grace — expires immediately
      });

      // No cache primed, fetch fails
      const result = await checker.checkRevocation(makeEntry(0), 'low');
      expect(result.decision).toBe('DENY');
      expect(result.denyCode).toBe('DENY_STATUS_SOURCE_UNAVAILABLE');
    });

    it('high-risk: DENY immediately even with stale cache', async () => {
      const fetchFn = mockFetchOk(credential);
      const checker = new StatusListRevocationChecker({
        fetchFn,
        cacheTtlMs: 1,
        offlineGraceMsLowRisk: 60_000,
      });

      // Prime cache
      await checker.checkRevocation(makeEntry(0), 'high');
      await new Promise(r => setTimeout(r, 10));

      // Make fetch fail
      (fetchFn as any).mockRejectedValue(new Error('offline'));

      // High-risk: no grace period
      const result = await checker.checkRevocation(makeEntry(0), 'high');
      expect(result.decision).toBe('DENY');
      expect(result.denyCode).toBe('DENY_STATUS_SOURCE_UNAVAILABLE');
    });
  });

  describe('batch check (privacy-preserving)', () => {
    it('deduplicates fetches for same URL', async () => {
      const fetchFn = mockFetchOk(credential);
      const checker = new StatusListRevocationChecker({ fetchFn });

      const results = await checker.checkRevocationBatch([
        { statusEntry: makeEntry(0), riskTier: 'high' },
        { statusEntry: makeEntry(5), riskTier: 'high' },
        { statusEntry: makeEntry(3), riskTier: 'low' },
      ]);

      // Only 1 fetch for the single unique URL
      expect(fetchFn).toHaveBeenCalledTimes(1);
      expect(results).toHaveLength(3);
      expect(results[0].decision).toBe('ALLOW');
      expect(results[1].decision).toBe('DENY'); // index 5 is revoked
      expect(results[2].decision).toBe('ALLOW');
    });
  });

  describe('edge cases', () => {
    it('invalid index (out of range) → DENY', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchOk(credential),
      });

      const result = await checker.checkRevocation(makeEntry(999));
      expect(result.decision).toBe('DENY');
      expect(result.reason).toBe('INVALID_INDEX');
      expect(result.denyCode).toBe('DENY_INTERNAL_SAFE_FAILURE');
    });

    it('negative index → DENY', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchOk(credential),
      });

      const entry = makeEntry(0);
      entry.statusListIndex = '-1';
      const result = await checker.checkRevocation(entry);
      expect(result.decision).toBe('DENY');
    });

    it('clearCache resets everything', () => {
      const checker = new StatusListRevocationChecker();
      checker.clearCache();
      expect(checker.getCacheStats().size).toBe(0);
    });
  });
});
