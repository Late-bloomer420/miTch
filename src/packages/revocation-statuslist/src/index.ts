/**
 * @package @mitch/revocation-statuslist
 * @description Privacy-preserving credential revocation using W3C StatusList2021
 *
 * Key design decisions:
 * - FAIL-CLOSED: any fetch failure or timeout → DENY (not ALLOW!)
 * - Privacy-preserving: batch fetch entire list, never per-credential queries
 * - Configurable TTL cache with offline grace period per risk tier
 * - Uses deny reason codes from @mitch/policy-engine
 *
 * @see https://www.w3.org/TR/vc-status-list/
 */

import type {
  StatusListCredential,
  StatusListEntry,
  RevocationCheckResult,
  StatusListCache,
  RiskTier,
  StatusListResolverOptions,
} from './types';

// Deny reason codes — inline strings to avoid cross-package dep at runtime.
// Values match @mitch/policy-engine DenyReasonCode enum.
const DENY_REVOKED = 'DENY_CREDENTIAL_REVOKED';
const DENY_STATUS_UNAVAILABLE = 'DENY_STATUS_SOURCE_UNAVAILABLE';
const DENY_INTERNAL = 'DENY_INTERNAL_SAFE_FAILURE';

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_FETCH_TIMEOUT_MS = 10_000; // 10 seconds
const DEFAULT_OFFLINE_GRACE_LOW_RISK_MS = 60 * 60 * 1000; // 1 hour

export class StatusListRevocationChecker {
  private cache: Map<string, StatusListCache> = new Map();
  private readonly cacheTtlMs: number;
  private readonly fetchTimeoutMs: number;
  private readonly offlineGraceMsLowRisk: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: StatusListResolverOptions = {}) {
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.fetchTimeoutMs = options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.offlineGraceMsLowRisk = options.offlineGraceMsLowRisk ?? DEFAULT_OFFLINE_GRACE_LOW_RISK_MS;
    this.fetchFn = options.fetchFn ?? globalThis.fetch?.bind(globalThis);
  }

  /**
   * Check if a credential is revoked via StatusList2021.
   *
   * Privacy: fetches entire status list (batch), never reveals which index is checked.
   * Fail-closed: fetch failure → DENY for high-risk, grace period for low-risk.
   *
   * @param statusEntry - The credentialStatus entry from the VC
   * @param riskTier - 'high' (Layer 1+, no grace) or 'low' (grace period allowed)
   */
  async checkRevocation(
    statusEntry: StatusListEntry,
    riskTier: RiskTier = 'high',
  ): Promise<RevocationCheckResult> {
    const listUrl = statusEntry.statusListCredential;
    const now = Date.now();

    // 1. Try cache
    const cached = this.cache.get(listUrl);

    if (cached && now < cached.expiresAt) {
      // Cache is fresh
      return this.checkBitstring(statusEntry, cached.credential, true);
    }

    // 2. Cache expired or missing — try to fetch
    try {
      const credential = await this.fetchStatusList(listUrl);

      // Update cache
      this.cache.set(listUrl, {
        url: listUrl,
        credential,
        fetchedAt: now,
        expiresAt: now + this.cacheTtlMs,
      });

      return this.checkBitstring(statusEntry, credential, false);
    } catch (_error) {
      // Fetch failed — apply fail-closed with grace period logic
      return this.handleFetchFailure(statusEntry, cached, riskTier, now);
    }
  }

  /**
   * Batch check multiple credentials against potentially the same status lists.
   * Privacy-preserving: deduplicates list fetches (one fetch per unique URL).
   */
  async checkRevocationBatch(
    entries: Array<{ statusEntry: StatusListEntry; riskTier?: RiskTier }>,
  ): Promise<RevocationCheckResult[]> {
    // Deduplicate URLs — fetch each list at most once
    const uniqueUrls = new Set(entries.map(e => e.statusEntry.statusListCredential));
    const fetchPromises = new Map<string, Promise<void>>();

    for (const url of uniqueUrls) {
      const cached = this.cache.get(url);
      if (cached && Date.now() < cached.expiresAt) continue; // Already fresh

      fetchPromises.set(url, this.prefetchStatusList(url));
    }

    // Wait for all fetches in parallel
    await Promise.allSettled(fetchPromises.values());

    // Now check each entry (all reads from cache)
    return Promise.all(
      entries.map(e => this.checkRevocation(e.statusEntry, e.riskTier ?? 'high')),
    );
  }

  /**
   * Prefetch a status list URL into cache. Errors are swallowed (handled in checkRevocation).
   */
  private async prefetchStatusList(url: string): Promise<void> {
    try {
      const credential = await this.fetchStatusList(url);
      const now = Date.now();
      this.cache.set(url, {
        url,
        credential,
        fetchedAt: now,
        expiresAt: now + this.cacheTtlMs,
      });
    } catch {
      // Swallow — checkRevocation will handle the failure
    }
  }

  /**
   * Handle fetch failure with fail-closed + grace period logic.
   */
  private handleFetchFailure(
    statusEntry: StatusListEntry,
    cached: StatusListCache | undefined,
    riskTier: RiskTier,
    now: number,
  ): RevocationCheckResult {
    // High-risk: no grace period — DENY immediately
    if (riskTier === 'high') {
      // Even if we have stale cache, high-risk = DENY
      return {
        decision: 'DENY',
        revoked: false,
        reason: 'STATUS_SOURCE_UNAVAILABLE',
        denyCode: DENY_STATUS_UNAVAILABLE,
        checkedAt: now,
        listUrl: statusEntry.statusListCredential,
        fromCache: false,
        graceMode: false,
      };
    }

    // Low-risk: check offline grace period
    if (cached) {
      const gracePeriodEnd = cached.expiresAt + this.offlineGraceMsLowRisk;

      if (now < gracePeriodEnd) {
        // Within grace period — use stale cache
        return this.checkBitstring(statusEntry, cached.credential, true, true);
      }
    }

    // Beyond grace period or no cache — DENY
    return {
      decision: 'DENY',
      revoked: false,
      reason: 'STATUS_SOURCE_UNAVAILABLE',
      denyCode: DENY_STATUS_UNAVAILABLE,
      checkedAt: now,
      listUrl: statusEntry.statusListCredential,
      fromCache: false,
      graceMode: false,
    };
  }

  /**
   * Fetch status list credential from URL with timeout.
   */
  private async fetchStatusList(url: string): Promise<StatusListCredential> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.fetchTimeoutMs);

    try {
      const response = await this.fetchFn(url, { signal: controller.signal });
      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`Status list fetch failed: HTTP ${response.status}`);
      }

      const credential = (await response.json()) as StatusListCredential;

      // Validate
      if (!credential.credentialSubject?.encodedList) {
        throw new Error('Invalid status list: missing encodedList');
      }
      if (credential.credentialSubject?.type !== 'StatusList2021') {
        throw new Error('Invalid status list: type is not StatusList2021');
      }

      return credential;
    } catch (e) {
      clearTimeout(timeout);
      throw e;
    }
  }

  /**
   * Check bitstring at given index.
   */
  private checkBitstring(
    statusEntry: StatusListEntry,
    credential: StatusListCredential,
    fromCache: boolean,
    graceMode = false,
  ): RevocationCheckResult {
    const index = parseInt(statusEntry.statusListIndex, 10);
    const now = Date.now();

    if (isNaN(index) || index < 0) {
      // Invalid index — fail-closed
      return {
        decision: 'DENY',
        revoked: false,
        reason: 'INVALID_INDEX',
        denyCode: DENY_INTERNAL,
        checkedAt: now,
        listUrl: statusEntry.statusListCredential,
        fromCache,
        graceMode,
      };
    }

    const encodedList = credential.credentialSubject.encodedList;
    const bitstring = this.decodeBase64Bitstring(encodedList);

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (byteIndex >= bitstring.length) {
      // Index out of range — fail-closed
      return {
        decision: 'DENY',
        revoked: false,
        reason: 'INVALID_INDEX',
        denyCode: DENY_INTERNAL,
        checkedAt: now,
        listUrl: statusEntry.statusListCredential,
        fromCache,
        graceMode,
      };
    }

    const byte = bitstring[byteIndex];
    const isRevoked = (byte & (1 << (7 - bitIndex))) !== 0; // MSB-first per spec

    if (isRevoked) {
      return {
        decision: 'DENY',
        revoked: true,
        reason: statusEntry.statusPurpose === 'revocation' ? 'REVOKED' : 'SUSPENDED',
        denyCode: DENY_REVOKED,
        checkedAt: now,
        listUrl: statusEntry.statusListCredential,
        fromCache,
        graceMode,
      };
    }

    return {
      decision: 'ALLOW',
      revoked: false,
      checkedAt: now,
      listUrl: statusEntry.statusListCredential,
      fromCache,
      graceMode,
    };
  }

  /**
   * Decode Base64-encoded bitstring to Uint8Array.
   * Handles both standard and URL-safe Base64.
   */
  private decodeBase64Bitstring(encoded: string): Uint8Array {
    const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /** Clear cache (for testing) */
  clearCache(): void {
    this.cache.clear();
  }

  /** Get cache stats (for monitoring) */
  getCacheStats(): { size: number; urls: string[] } {
    return {
      size: this.cache.size,
      urls: Array.from(this.cache.keys()),
    };
  }

  /** Expose cache for testing */
  getCacheEntry(url: string): StatusListCache | undefined {
    return this.cache.get(url);
  }
}

export * from './types';
