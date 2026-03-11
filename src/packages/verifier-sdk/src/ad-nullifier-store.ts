/**
 * @module @mitch/verifier-sdk/ad-nullifier-store
 *
 * NullifierStore interface and implementations for ad-tech frequency capping.
 *
 * Verifiers use nullifiers to count impressions per user per scope
 * without learning who the user is. The nullifier is unlinkable across
 * scopes (verifier_did in formula) — verifiers cannot share nullifier data.
 *
 * GDPR note: Nullifiers are pseudonymous. Retain only for campaign duration + 30 days.
 * On Art. 17 erasure request: call delete(nullifier, scopeId) for each scope.
 */

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * Pluggable nullifier store.
 * Implementations: InMemoryNullifierStore (test), RedisNullifierStore (production).
 */
export interface NullifierStore {
    /** Check if nullifier has been seen for this scope */
    exists(nullifier: string, scopeId: string): Promise<boolean>;

    /** Record a new nullifier (idempotent) */
    record(nullifier: string, scopeId: string, ttlSeconds?: number): Promise<void>;

    /** Get impression count for nullifier in scope */
    getCount(nullifier: string, scopeId: string): Promise<number>;

    /**
     * Increment count and return new value.
     * Must be atomic to prevent race conditions.
     */
    incrementCount(nullifier: string, scopeId: string, ttlSeconds?: number): Promise<number>;

    /** Delete nullifier — for GDPR Art. 17 erasure */
    delete(nullifier: string, scopeId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// In-memory implementation (testing / single-process use)
// ---------------------------------------------------------------------------

interface Entry {
    count: number;
    expiresAt?: number; // Unix ms
}

/**
 * In-memory NullifierStore.
 * NOT for production — does not survive restarts, not shared across processes.
 * Use for unit tests and single-process integration tests.
 */
export class InMemoryNullifierStore implements NullifierStore {
    private store = new Map<string, Entry>();

    private key(nullifier: string, scopeId: string): string {
        return `${scopeId}::${nullifier}`;
    }

    private isExpired(entry: Entry): boolean {
        return entry.expiresAt !== undefined && Date.now() > entry.expiresAt;
    }

    async exists(nullifier: string, scopeId: string): Promise<boolean> {
        const entry = this.store.get(this.key(nullifier, scopeId));
        if (!entry || this.isExpired(entry)) return false;
        return entry.count > 0;
    }

    async record(nullifier: string, scopeId: string, ttlSeconds?: number): Promise<void> {
        const k = this.key(nullifier, scopeId);
        if (!this.store.has(k)) {
            this.store.set(k, {
                count: 1,
                expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
            });
        }
    }

    async getCount(nullifier: string, scopeId: string): Promise<number> {
        const entry = this.store.get(this.key(nullifier, scopeId));
        if (!entry || this.isExpired(entry)) return 0;
        return entry.count;
    }

    async incrementCount(nullifier: string, scopeId: string, ttlSeconds?: number): Promise<number> {
        const k = this.key(nullifier, scopeId);
        const existing = this.store.get(k);
        if (!existing || this.isExpired(existing)) {
            this.store.set(k, {
                count: 1,
                expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
            });
            return 1;
        }
        existing.count += 1;
        return existing.count;
    }

    async delete(nullifier: string, scopeId: string): Promise<void> {
        this.store.delete(this.key(nullifier, scopeId));
    }

    /** Test helper — clear all entries */
    clear(): void {
        this.store.clear();
    }

    /** Test helper — count total entries */
    size(): number {
        return this.store.size;
    }
}

// ---------------------------------------------------------------------------
// Redis stub (production — requires ioredis / @upstash/redis)
// ---------------------------------------------------------------------------

/**
 * Redis-backed NullifierStore stub.
 *
 * Full implementation requires a Redis client (ioredis, @upstash/redis, etc.).
 * This stub documents the expected interface and key structure.
 *
 * Key format: `mitch:nullifier:{scopeId}:{nullifier}`
 * TTL: set on incrementCount, typically campaign duration (7 days default).
 *
 * Atomicity: use INCR command (atomic in Redis single-threaded model).
 */
export class RedisNullifierStore implements NullifierStore {
    constructor(
        private readonly options: {
            /** Redis client with get/set/incr/del/exists methods */
            client: {
                get(key: string): Promise<string | null>;
                set(key: string, value: string, ex?: number): Promise<unknown>;
                incr(key: string): Promise<number>;
                expire(key: string, seconds: number): Promise<unknown>;
                del(key: string): Promise<unknown>;
                exists(key: string): Promise<number>;
            };
            keyPrefix?: string;
            defaultTtlSeconds?: number;
        }
    ) { }

    private key(nullifier: string, scopeId: string): string {
        const prefix = this.options.keyPrefix ?? 'mitch:nullifier:';
        return `${prefix}${scopeId}:${nullifier}`;
    }

    async exists(nullifier: string, scopeId: string): Promise<boolean> {
        const count = await this.options.client.exists(this.key(nullifier, scopeId));
        return count > 0;
    }

    async record(nullifier: string, scopeId: string, ttlSeconds?: number): Promise<void> {
        const k = this.key(nullifier, scopeId);
        const ttl = ttlSeconds ?? this.options.defaultTtlSeconds;
        await this.options.client.set(k, '1', ttl);
    }

    async getCount(nullifier: string, scopeId: string): Promise<number> {
        const val = await this.options.client.get(this.key(nullifier, scopeId));
        return val ? parseInt(val, 10) : 0;
    }

    async incrementCount(nullifier: string, scopeId: string, ttlSeconds?: number): Promise<number> {
        const k = this.key(nullifier, scopeId);
        const count = await this.options.client.incr(k);
        if (count === 1) {
            // First increment — set TTL
            const ttl = ttlSeconds ?? this.options.defaultTtlSeconds;
            if (ttl) await this.options.client.expire(k, ttl);
        }
        return count;
    }

    async delete(nullifier: string, scopeId: string): Promise<void> {
        await this.options.client.del(this.key(nullifier, scopeId));
    }
}
