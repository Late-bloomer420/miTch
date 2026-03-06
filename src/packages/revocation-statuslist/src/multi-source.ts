/**
 * Spec 62 — Revocation Status Resolver v2
 * Multi-source resolution with fallback chain and cache.
 *
 * Design:
 * - Try primary URL, on failure try fallback URLs in order
 * - Each source can have different TTLs
 * - Fail-closed: all sources fail → DENY
 */

import type { StatusListEntry, RevocationCheckResult, RiskTier } from './types';
import { StatusListRevocationChecker } from './index';

export interface SourceConfig {
    url: string;
    ttlMs?: number;
    priority?: number; // lower = tried first
}

export interface MultiSourceResolverOptions {
    fetchTimeoutMs?: number;
    fetchFn?: typeof fetch;
    /** Max attempts per source before moving to next */
    maxAttemptsPerSource?: number;
}

export interface MultiSourceResult extends RevocationCheckResult {
    resolvedFrom?: string;
    attemptedSources?: string[];
    fallbackUsed?: boolean;
}

/**
 * Multi-source StatusList2021 resolver with fallback chain.
 * Tries sources in priority order; first success wins.
 */
export class MultiSourceStatusResolver {
    private readonly checkers: Map<string, StatusListRevocationChecker>;
    private readonly options: MultiSourceResolverOptions;

    constructor(options: MultiSourceResolverOptions = {}) {
        this.options = options;
        this.checkers = new Map();
    }

    /**
     * Resolve revocation status with fallback chain.
     * @param entry - Status list entry from the credential
     * @param fallbackUrls - Additional URLs to try if primary fails
     * @param riskTier - Risk tier for fail-closed behavior
     */
    async resolve(
        entry: StatusListEntry,
        fallbackUrls: string[] = [],
        riskTier: RiskTier = 'high'
    ): Promise<MultiSourceResult> {
        const sources = [entry.statusListCredential, ...fallbackUrls];
        const attempted: string[] = [];

        for (let i = 0; i < sources.length; i++) {
            const url = sources[i];
            attempted.push(url);

            const checker = this.getOrCreateChecker(url);
            const modifiedEntry: StatusListEntry = { ...entry, statusListCredential: url };

            try {
                const result = await checker.checkRevocation(modifiedEntry, riskTier);
                if (result.decision === 'ALLOW' || result.reason === 'REVOKED' || result.reason === 'SUSPENDED') {
                    // Got a definitive answer — success or credential actually revoked
                    return {
                        ...result,
                        resolvedFrom: url,
                        attemptedSources: attempted,
                        fallbackUsed: i > 0,
                    };
                }
                // Source returned DENY due to unavailability — try next
            } catch {
                // Try next source
            }
        }

        // All sources failed
        return {
            decision: 'DENY',
            revoked: false,
            reason: 'ALL_SOURCES_UNAVAILABLE',
            denyCode: 'DENY_STATUS_SOURCE_UNAVAILABLE',
            checkedAt: Date.now(),
            listUrl: entry.statusListCredential,
            fromCache: false,
            graceMode: false,
            resolvedFrom: undefined,
            attemptedSources: attempted,
            fallbackUsed: attempted.length > 1,
        };
    }

    /**
     * Batch check with multi-source resolution.
     */
    async resolveBatch(
        entries: Array<{
            entry: StatusListEntry;
            fallbackUrls?: string[];
            riskTier?: RiskTier;
        }>
    ): Promise<MultiSourceResult[]> {
        return Promise.all(
            entries.map(({ entry, fallbackUrls, riskTier }) =>
                this.resolve(entry, fallbackUrls ?? [], riskTier ?? 'high')
            )
        );
    }

    private getOrCreateChecker(url: string): StatusListRevocationChecker {
        if (!this.checkers.has(url)) {
            this.checkers.set(url, new StatusListRevocationChecker({
                fetchTimeoutMs: this.options.fetchTimeoutMs,
                fetchFn: this.options.fetchFn,
            }));
        }
        return this.checkers.get(url)!;
    }

    /** Clear all caches */
    clearAllCaches(): void {
        for (const checker of this.checkers.values()) {
            checker.clearCache();
        }
    }

    get sourceCount(): number {
        return this.checkers.size;
    }
}

// ─── StatusList2021 Bitstring utilities (Spec 68) ─────────────────

/**
 * Decode a Base64-encoded StatusList2021 bitstring.
 * Handles standard and URL-safe Base64.
 */
export function decodeStatusListBitstring(encodedList: string): Uint8Array {
    const base64 = encodedList.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Check if a bit at a given index is set in a bitstring.
 * StatusList2021 uses MSB-first bit ordering per spec.
 */
export function checkBitstringIndex(bitstring: Uint8Array, index: number): boolean {
    if (index < 0 || Math.floor(index / 8) >= bitstring.length) {
        throw new RangeError(`Index ${index} out of range for bitstring of ${bitstring.length * 8} bits`);
    }
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    return (bitstring[byteIndex] & (1 << (7 - bitIndex))) !== 0;
}

/**
 * Encode a set of revoked indices into a StatusList2021 bitstring.
 * Useful for testing and issuer-side generation.
 */
export function encodeStatusListBitstring(totalEntries: number, revokedIndices: number[]): string {
    const byteCount = Math.ceil(totalEntries / 8);
    const bytes = new Uint8Array(byteCount);

    for (const index of revokedIndices) {
        if (index >= 0 && index < totalEntries) {
            const byteIndex = Math.floor(index / 8);
            const bitIndex = index % 8;
            bytes[byteIndex] |= (1 << (7 - bitIndex));
        }
    }

    const binary = Array.from(bytes).map(b => String.fromCharCode(b)).join('');
    return btoa(binary);
}

/**
 * Extract all revoked indices from a bitstring.
 */
export function extractRevokedIndices(bitstring: Uint8Array): number[] {
    const revoked: number[] = [];
    for (let byteIdx = 0; byteIdx < bitstring.length; byteIdx++) {
        for (let bit = 0; bit < 8; bit++) {
            if (bitstring[byteIdx] & (1 << (7 - bit))) {
                revoked.push(byteIdx * 8 + bit);
            }
        }
    }
    return revoked;
}
