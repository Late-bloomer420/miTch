export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    resetInMs: number;
    limit: number;
}

interface RateLimitEntry {
    windowStart: number;
    count: number;
}

export class FixedWindowRateLimiter {
    private entries = new Map<string, RateLimitEntry>();
    private maxEntries: number;
    private pruneIntervalMs: number;
    private lastPruneAt = 0;

    constructor(
        private windowMs: number,
        private maxRequests: number,
        options?: {
            maxEntries?: number;
            pruneIntervalMs?: number;
        }
    ) {
        this.maxEntries = options?.maxEntries ?? 100_000;
        this.pruneIntervalMs = options?.pruneIntervalMs ?? 30_000;
    }

    check(key: string, now: number = Date.now()): RateLimitResult {
        let entry = this.entries.get(key);

        if (!entry || (now - entry.windowStart) >= this.windowMs) {
            entry = { windowStart: now, count: 0 };
        }

        if (entry.count >= this.maxRequests) {
            const resetInMs = Math.max(0, (entry.windowStart + this.windowMs) - now);
            this.entries.set(key, entry);
            this.pruneIfNeeded(now);
            return {
                allowed: false,
                remaining: 0,
                resetInMs,
                limit: this.maxRequests
            };
        }

        // T-39: Atomic Increment & Jitter
        entry.count += 1;
        this.entries.set(key, entry);

        // Security: Add stochastic jitter to reset time to prevent timing attacks (window inference)
        const rawResetInMs = Math.max(0, (entry.windowStart + this.windowMs) - now);
        const jitter = Math.floor(Math.random() * 1000); // 0-1000ms jitter

        const result = {
            allowed: true,
            remaining: Math.max(0, this.maxRequests - entry.count),
            resetInMs: rawResetInMs + jitter,
            limit: this.maxRequests
        };

        this.pruneIfNeeded(now);
        return result;
    }

    size(): number {
        return this.entries.size;
    }

    private pruneIfNeeded(now: number): void {
        if (this.entries.size > this.maxEntries) {
            this.lastPruneAt = now;
            this.prune(now);
            return;
        }
        if (now - this.lastPruneAt < this.pruneIntervalMs) return;
        this.lastPruneAt = now;
        this.prune(now);
    }

    private prune(now: number): void {
        // T-39: LRU-style cleanup based on window expiration
        for (const [key, value] of this.entries) {
            // If window is fully passed (+grace period if needed), remove it
            if ((now - value.windowStart) >= this.windowMs) {
                this.entries.delete(key);
            }
        }

        if (this.entries.size <= this.maxEntries) return;

        const overflow = this.entries.size - this.maxEntries;
        let removed = 0;
        for (const key of this.entries.keys()) {
            this.entries.delete(key);
            removed += 1;
            if (removed >= overflow) break;
        }
    }
}
