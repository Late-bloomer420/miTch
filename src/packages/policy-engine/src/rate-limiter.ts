/**
 * Rate Limiting for Policy Engine (Specs 48, 57)
 *
 * Per-verifier and per-user rate limiting.
 * Mirrors poc-hardened rateLimiter but as policy-engine integration.
 */

export interface RateLimitConfig {
    /** Max requests per window */
    maxRequests: number;
    /** Window size in ms */
    windowMs: number;
    /** Optional: separate limit per user */
    perUserMaxRequests?: number;
}

export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    resetAt: number;
    reason?: string;
}

interface WindowEntry {
    timestamps: number[];
    /** Earliest timestamp in window (for reset calculation) */
    windowStart: number;
}

export class PolicyRateLimiter {
    private readonly verifierWindows = new Map<string, WindowEntry>();
    private readonly userWindows = new Map<string, WindowEntry>();
    private readonly config: Required<RateLimitConfig>;

    constructor(config: RateLimitConfig) {
        this.config = {
            perUserMaxRequests: config.maxRequests,
            ...config,
        };
    }

    /**
     * Check and record a request from verifier/user pair.
     */
    check(verifierId: string, userId: string): RateLimitResult {
        const now = Date.now();

        // Check verifier limit
        const verifierResult = this.checkWindow(
            this.verifierWindows,
            verifierId,
            this.config.maxRequests,
            now
        );
        if (!verifierResult.allowed) {
            return { ...verifierResult, reason: `RATE_LIMIT_VERIFIER:${verifierId}` };
        }

        // Check user limit
        const userResult = this.checkWindow(
            this.userWindows,
            userId,
            this.config.perUserMaxRequests,
            now
        );
        if (!userResult.allowed) {
            return { ...userResult, reason: `RATE_LIMIT_USER:${userId}` };
        }

        // Record the request
        this.recordWindow(this.verifierWindows, verifierId, now);
        this.recordWindow(this.userWindows, userId, now);

        return {
            allowed: true,
            remaining: Math.min(verifierResult.remaining, userResult.remaining) - 1,
            resetAt: Math.max(verifierResult.resetAt, userResult.resetAt),
        };
    }

    /**
     * Check limit for verifier only (no user tracking).
     */
    checkVerifier(verifierId: string): RateLimitResult {
        const now = Date.now();
        const result = this.checkWindow(this.verifierWindows, verifierId, this.config.maxRequests, now);
        if (result.allowed) {
            this.recordWindow(this.verifierWindows, verifierId, now);
        }
        return result;
    }

    private checkWindow(
        store: Map<string, WindowEntry>,
        key: string,
        max: number,
        now: number
    ): RateLimitResult {
        const cutoff = now - this.config.windowMs;
        const entry = store.get(key);

        if (!entry) {
            return { allowed: true, remaining: max, resetAt: now + this.config.windowMs };
        }

        const recent = entry.timestamps.filter(t => t >= cutoff);
        const resetAt = recent.length > 0 ? recent[0] + this.config.windowMs : now + this.config.windowMs;

        if (recent.length >= max) {
            return {
                allowed: false,
                remaining: 0,
                resetAt,
                reason: 'RATE_LIMIT_EXCEEDED',
            };
        }

        return { allowed: true, remaining: max - recent.length, resetAt };
    }

    private recordWindow(store: Map<string, WindowEntry>, key: string, now: number): void {
        const cutoff = now - this.config.windowMs;
        const entry = store.get(key) ?? { timestamps: [], windowStart: now };
        entry.timestamps = entry.timestamps.filter(t => t >= cutoff);
        entry.timestamps.push(now);
        store.set(key, entry);
    }

    /**
     * Reset limits for a specific verifier (admin action).
     */
    resetVerifier(verifierId: string): void {
        this.verifierWindows.delete(verifierId);
    }

    resetUser(userId: string): void {
        this.userWindows.delete(userId);
    }

    getVerifierCount(verifierId: string): number {
        const now = Date.now();
        const entry = this.verifierWindows.get(verifierId);
        if (!entry) return 0;
        return entry.timestamps.filter(t => t >= now - this.config.windowMs).length;
    }

    getConfig(): Required<RateLimitConfig> {
        return { ...this.config };
    }
}
