/**
 * @package @askmi/revocation-statuslist
 * @description Privacy-preserving credential revocation using W3C StatusList2021
 *
 * Key design decisions:
 * - FAIL-CLOSED: any fetch failure or timeout → DENY (not ALLOW!)
 * - Privacy-preserving: batch fetch entire list, never per-credential queries
 * - Configurable TTL cache with offline grace period per risk tier
 * - Uses deny reason codes from @askmi/policy-engine
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
  StatusListMode,
  StatusListKeyResolver,
} from './types.js';

// Deny reason codes — inline strings to avoid cross-package dep at runtime.
// Values match @askmi/policy-engine DenyReasonCode enum.
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
  private readonly statusListMode: StatusListMode;
  private resolveStatusListKey: StatusListKeyResolver | undefined;

  constructor(options: StatusListResolverOptions = {}) {
    this.statusListMode = options.statusListMode ?? (readTrustModeEnv() === 'dev' ? 'dev' : 'live');
    this.resolveStatusListKey = options.resolveStatusListKey;
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
    } catch (_error: unknown) {
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
      const response = await this.fetchFn(url, {
        signal: controller.signal,
        headers: { Accept: 'application/vc+jwt, application/statuslist+jwt, application/json;q=0.1' },
      });
      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`Status list fetch failed: HTTP ${response.status}`);
      }

      const body: unknown =
        typeof response.text === 'function' ? await response.text() : await response.json();
      const credential = await this.authenticateStatusList(body);

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

  /** Replace the status-list issuer key resolver (e.g. wired by the verifier at startup). */
  setStatusListKeyResolver(resolver: StatusListKeyResolver | undefined): void {
    this.resolveStatusListKey = resolver;
    this.cache.clear();
  }

  /**
   * API-05: return the status list only if its origin is authenticated.
   * A compact JWS is verified (ES256, typ vc+jwt|statuslist+jwt, key by issuer/kid,
   * iss == credential.issuer, exp/nbf). Unsigned JSON is accepted only in `dev` mode.
   */
  private async authenticateStatusList(body: unknown): Promise<StatusListCredential> {
    const text = typeof body === 'string' ? body.trim() : null;
    if (text !== null && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) {
      return this.verifySignedStatusList(text);
    }
    if (this.statusListMode !== 'dev') {
      throw new Error('Unsigned status list rejected (live mode requires a signed status list)');
    }
    return (text !== null ? JSON.parse(text) : body) as StatusListCredential;
  }

  private async verifySignedStatusList(jws: string): Promise<StatusListCredential> {
    const [h, p, sig] = jws.split('.');
    const header = JSON.parse(utf8(base64urlDecode(h))) as { alg?: string; typ?: string; kid?: string };
    if (header.alg !== 'ES256') throw new Error('Status list: unsupported alg');
    const typ = header.typ?.toLowerCase();
    if (typ !== 'vc+jwt' && typ !== 'statuslist+jwt') throw new Error('Status list: invalid typ');
    const payload = JSON.parse(utf8(base64urlDecode(p))) as {
      iss?: string;
      exp?: number;
      nbf?: number;
      vc?: StatusListCredential;
    } & Partial<StatusListCredential>;
    const credential = (payload.vc ?? payload) as StatusListCredential;
    const issuer = payload.iss ?? credential.issuer;
    if (!issuer || (credential.issuer && credential.issuer !== issuer)) {
      throw new Error('Status list: issuer mismatch');
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && nowSec >= payload.exp) throw new Error('Status list: expired');
    if (typeof payload.nbf === 'number' && nowSec < payload.nbf) throw new Error('Status list: not yet valid');
    if (!this.resolveStatusListKey) throw new Error('Status list: no issuer key resolver configured');
    const key = await this.resolveStatusListKey(issuer, header.kid);
    if (!key) throw new Error('Status list: issuer key not resolvable');
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      base64urlDecode(sig),
      new TextEncoder().encode(`${h}.${p}`),
    );
    if (!ok) throw new Error('Status list: signature invalid');
    return credential;
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

function base64urlDecode(input: string): Uint8Array<ArrayBuffer> {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function utf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** Same switch as the trust-list resolver; browser- and Node-safe. */
function readTrustModeEnv(): string | undefined {
  const importMetaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
  const maybeProcess = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return (importMetaEnv?.ASKMI_TRUST_MODE ?? maybeProcess?.env?.ASKMI_TRUST_MODE)?.trim();
}

export * from './types.js';
export * from './multi-source.js';
