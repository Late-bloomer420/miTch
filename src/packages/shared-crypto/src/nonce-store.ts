/**
 * @module @mitch/shared-crypto/nonce-store
 *
 * Anti-replay nonce store with TTL, audience binding, and clock-skew tolerance.
 *
 * Design: fail-closed. Any ambiguity = DENY.
 *
 * Spec: docs/specs/108_Presentation_Binding_AntiReplay_Spec_v1.md
 */

import { crypto } from './platform';

// ── Deny codes ──────────────────────────────────────────────────────────────

export const DENY_BINDING_NONCE_UNKNOWN = 'DENY_BINDING_NONCE_UNKNOWN';
export const DENY_BINDING_NONCE_REPLAY = 'DENY_BINDING_NONCE_REPLAY';
export const DENY_BINDING_EXPIRED = 'DENY_BINDING_EXPIRED';
export const DENY_BINDING_AUDIENCE_MISMATCH = 'DENY_BINDING_AUDIENCE_MISMATCH';
export const DENY_BINDING_HASH_MISMATCH = 'DENY_BINDING_HASH_MISMATCH';
export const DENY_SCHEMA_MISSING_FIELD = 'DENY_SCHEMA_MISSING_FIELD';

// ── Types ───────────────────────────────────────────────────────────────────

export interface NonceEntry {
    /** Audience (verifier identifier) this nonce is bound to */
    audience: string;
    /** Absolute expiry timestamp (ms since epoch) */
    expiresAt: number;
    /** Whether the nonce has already been consumed */
    consumed: boolean;
}

export interface NonceStoreConfig {
    /** Nonce TTL in milliseconds. Default: 5 minutes. */
    ttlMs?: number;
    /** Maximum entries before oldest are evicted. Default: 100_000. */
    maxEntries?: number;
    /** Clock skew tolerance in milliseconds. Default: 30_000 (±30s). */
    clockSkewMs?: number;
}

export type ConsumeResult =
    | { ok: true }
    | { ok: false; code: string };

const DEFAULT_TTL_MS = 5 * 60 * 1000;       // 5 minutes
const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_CLOCK_SKEW_MS = 30 * 1000;     // ±30 seconds
const NONCE_BYTES = 32;

// ── Nonce generation ────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random nonce (32 bytes, hex-encoded).
 */
export function generateNonce(): string {
    const bytes = new Uint8Array(NONCE_BYTES);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── NonceStore ──────────────────────────────────────────────────────────────

export class BindingNonceStore {
    private entries = new Map<string, NonceEntry>();
    private readonly ttlMs: number;
    private readonly maxEntries: number;
    private readonly clockSkewMs: number;

    constructor(config: NonceStoreConfig = {}) {
        this.ttlMs = config.ttlMs ?? DEFAULT_TTL_MS;
        this.maxEntries = config.maxEntries ?? DEFAULT_MAX_ENTRIES;
        this.clockSkewMs = config.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    }

    /** Composite key for the map. */
    private key(audience: string, nonce: string): string {
        return `${audience}\0${nonce}`;
    }

    /**
     * Issue a new nonce bound to an audience.
     * Returns the nonce string and its absolute expiry.
     */
    issue(audience: string, now: number = Date.now()): { nonce: string; expiresAt: number } {
        this.pruneExpired(now);
        this.evictIfFull();

        const nonce = generateNonce();
        const expiresAt = now + this.ttlMs;

        this.entries.set(this.key(audience, nonce), {
            audience,
            expiresAt,
            consumed: false,
        });

        return { nonce, expiresAt };
    }

    /**
     * Register an externally-created nonce (e.g. from a presentation request).
     */
    register(audience: string, nonce: string, expiresAt: number, now: number = Date.now()): void {
        this.pruneExpired(now);
        this.evictIfFull();

        this.entries.set(this.key(audience, nonce), {
            audience,
            expiresAt,
            consumed: false,
        });
    }

    /**
     * Consume a nonce atomically. Single-use: returns ok:true exactly once.
     *
     * Validation order (per spec §5):
     * 1. Nonce exists → else DENY_BINDING_NONCE_UNKNOWN
     * 2. Not expired (with skew) → else DENY_BINDING_EXPIRED
     * 3. Audience matches → else DENY_BINDING_AUDIENCE_MISMATCH
     * 4. Not already consumed → else DENY_BINDING_NONCE_REPLAY
     * 5. Mark consumed + remove.
     */
    consume(audience: string, nonce: string, now: number = Date.now()): ConsumeResult {
        const k = this.key(audience, nonce);
        const entry = this.entries.get(k);

        // 1. Exists?
        if (!entry) {
            return { ok: false, code: DENY_BINDING_NONCE_UNKNOWN };
        }

        // 2. Expired? (expiresAt + clockSkew < now means truly expired)
        if (entry.expiresAt + this.clockSkewMs < now) {
            this.entries.delete(k);
            return { ok: false, code: DENY_BINDING_EXPIRED };
        }

        // 3. Audience match?
        if (entry.audience !== audience) {
            // This shouldn't happen with composite key, but defense-in-depth
            return { ok: false, code: DENY_BINDING_AUDIENCE_MISMATCH };
        }

        // 4. Already consumed?
        if (entry.consumed) {
            return { ok: false, code: DENY_BINDING_NONCE_REPLAY };
        }

        // 5. Consume atomically
        entry.consumed = true;
        this.entries.delete(k); // Remove after consumption — single use
        return { ok: true };
    }

    /**
     * Check if a nonce exists and is valid (without consuming).
     */
    has(audience: string, nonce: string, now: number = Date.now()): boolean {
        const entry = this.entries.get(this.key(audience, nonce));
        if (!entry) return false;
        if (entry.expiresAt + this.clockSkewMs < now) return false;
        if (entry.consumed) return false;
        return true;
    }

    /** Current number of entries. */
    get size(): number {
        return this.entries.size;
    }

    /** Remove all expired entries. */
    pruneExpired(now: number = Date.now()): void {
        for (const [k, entry] of this.entries) {
            if (entry.expiresAt + this.clockSkewMs < now) {
                this.entries.delete(k);
            }
        }
    }

    /** Evict oldest entries if over capacity. */
    private evictIfFull(): void {
        if (this.entries.size <= this.maxEntries) return;
        const overflow = this.entries.size - this.maxEntries;
        const iter = this.entries.keys();
        for (let i = 0; i < overflow; i++) {
            const r = iter.next();
            if (r.done) break;
            this.entries.delete(r.value);
        }
    }

    /** Clear all entries. */
    clear(): void {
        this.entries.clear();
    }
}
