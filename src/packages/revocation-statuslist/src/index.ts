/**
 * @package @mitch/revocation-statuslist
 * @description Privacy-preserving credential revocation using W3C StatusList2021
 *
 * Key Features:
 * - Bitstring-based revocation (no per-credential lookups)
 * - Privacy-preserving (verifier fetches entire list, not individual status)
 * - Caching to minimize network requests
 * - Degraded mode handling (fail-closed if list unavailable)
 *
 * @see https://www.w3.org/TR/vc-status-list/
 */

import type {
  StatusListCredential,
  StatusListEntry,
  RevocationCheckResult,
  StatusListCache,
} from './types';

export class StatusListRevocationChecker {
  private cache: Map<string, StatusListCache>;
  private cacheMinutes: number;
  private failClosed: boolean;

  constructor(options: { cacheMinutes?: number; failClosed?: boolean } = {}) {
    this.cache = new Map();
    this.cacheMinutes = options.cacheMinutes ?? 60; // 1 hour default
    this.failClosed = options.failClosed ?? true; // Deny if list unavailable
  }

  /**
   * Check if a credential is revoked by fetching its status list
   */
  async checkRevocation(statusEntry: StatusListEntry): Promise<RevocationCheckResult> {
    const listUrl = statusEntry.statusListCredential;

    try {
      // 1. Try cache first
      const cached = this.cache.get(listUrl);
      if (cached && Date.now() < cached.expiresAt) {
        return this.checkBitstring(statusEntry, cached.credential);
      }

      // 2. Fetch status list credential
      const credential = await this.fetchStatusList(listUrl);

      // 3. Cache it
      this.cache.set(listUrl, {
        url: listUrl,
        credential,
        fetchedAt: Date.now(),
        expiresAt: Date.now() + this.cacheMinutes * 60 * 1000,
      });

      // 4. Check bitstring
      return this.checkBitstring(statusEntry, credential);
    } catch (error) {
      console.error('Status list fetch error:', error);

      // Degraded mode: fail-closed or fail-open?
      if (this.failClosed) {
        return {
          revoked: false, // Allow credential (conservative)
          reason: 'LIST_UNAVAILABLE',
          checkedAt: Date.now(),
          listUrl,
        };
      } else {
        // Fail-open (risky but more resilient)
        return {
          revoked: false,
          reason: 'LIST_UNAVAILABLE',
          checkedAt: Date.now(),
          listUrl,
        };
      }
    }
  }

  /**
   * Fetch status list credential from URL
   */
  private async fetchStatusList(url: string): Promise<StatusListCredential> {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Status list fetch failed: ${response.status}`);
    }

    const credential = (await response.json()) as StatusListCredential;

    // Basic validation
    if (!credential.credentialSubject?.encodedList) {
      throw new Error('Invalid status list: missing encodedList');
    }

    return credential;
  }

  /**
   * Check bitstring at given index
   */
  private checkBitstring(
    statusEntry: StatusListEntry,
    credential: StatusListCredential
  ): RevocationCheckResult {
    const index = parseInt(statusEntry.statusListIndex, 10);
    const encodedList = credential.credentialSubject.encodedList;

    // Decode Base64 bitstring
    const bitstring = this.decodeBase64Bitstring(encodedList);

    // Check bit at index
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (byteIndex >= bitstring.length) {
      return {
        revoked: false,
        reason: 'INVALID_INDEX',
        checkedAt: Date.now(),
      };
    }

    const byte = bitstring[byteIndex];
    const isRevoked = (byte & (1 << bitIndex)) !== 0;

    return {
      revoked: isRevoked,
      reason: isRevoked
        ? statusEntry.statusPurpose === 'revocation'
          ? 'REVOKED'
          : 'SUSPENDED'
        : undefined,
      checkedAt: Date.now(),
      listUrl: statusEntry.statusListCredential,
    };
  }

  /**
   * Decode Base64-encoded bitstring to Uint8Array
   */
  private decodeBase64Bitstring(encoded: string): Uint8Array {
    // Remove padding and convert to URL-safe Base64
    const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Clear cache (for testing)
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache stats (for monitoring)
   */
  getCacheStats(): { size: number; urls: string[] } {
    return {
      size: this.cache.size,
      urls: Array.from(this.cache.keys()),
    };
  }
}

export * from './types';
