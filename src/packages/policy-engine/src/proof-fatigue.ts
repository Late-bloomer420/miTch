/**
 * Proof Fatigue Protection (Spec 48, 57)
 *
 * Tracks how often a user has been prompted for proofs in a time window.
 * After N prompts within X minutes, automatically DENY + warn.
 * Mirrors poc-hardened/src/api/proofFatigue.ts but integrated with policy-engine.
 */

export interface FatigueConfig {
    /** Max prompts before fatigue triggers (default: 5) */
    maxPromptsPerWindow: number;
    /** Window size in ms (default: 10 minutes) */
    windowMs: number;
    /** Whether to automatically DENY (true) or just flag (false) */
    autoDeny: boolean;
}

export interface FatigueState {
    userId: string;
    promptTimestamps: number[];
    fatigued: boolean;
    fatiguedAt?: number;
}

export interface FatigueCheckResult {
    fatigued: boolean;
    promptCount: number;
    remaining: number;
    action: 'allow_prompt' | 'warn' | 'deny';
    reason?: string;
}

const DEFAULT_CONFIG: FatigueConfig = {
    maxPromptsPerWindow: 5,
    windowMs: 10 * 60 * 1000, // 10 minutes
    autoDeny: true,
};

export class ProofFatigueTracker {
    private readonly states = new Map<string, FatigueState>();
    private readonly config: FatigueConfig;

    constructor(config: Partial<FatigueConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Record a proof prompt for a user and check fatigue.
     */
    recordPrompt(userId: string): FatigueCheckResult {
        const now = Date.now();
        const cutoff = now - this.config.windowMs;

        const state = this.states.get(userId) ?? { userId, promptTimestamps: [], fatigued: false };

        // Prune old timestamps
        state.promptTimestamps = state.promptTimestamps.filter(ts => ts >= cutoff);

        // Add current prompt
        state.promptTimestamps.push(now);

        const count = state.promptTimestamps.length;
        const remaining = Math.max(0, this.config.maxPromptsPerWindow - count);

        if (count > this.config.maxPromptsPerWindow) {
            state.fatigued = true;
            state.fatiguedAt = now;
            this.states.set(userId, state);

            return {
                fatigued: true,
                promptCount: count,
                remaining: 0,
                action: this.config.autoDeny ? 'deny' : 'warn',
                reason: `PROOF_FATIGUE: ${count} prompts in ${this.config.windowMs / 60000} minutes`,
            };
        }

        // Warning at 80% threshold
        const isWarning = count >= Math.ceil(this.config.maxPromptsPerWindow * 0.8);
        this.states.set(userId, state);

        return {
            fatigued: false,
            promptCount: count,
            remaining,
            action: isWarning ? 'warn' : 'allow_prompt',
        };
    }

    /**
     * Check fatigue state without recording a prompt.
     */
    checkFatigue(userId: string): FatigueCheckResult {
        const now = Date.now();
        const cutoff = now - this.config.windowMs;

        const state = this.states.get(userId);
        if (!state) {
            return { fatigued: false, promptCount: 0, remaining: this.config.maxPromptsPerWindow, action: 'allow_prompt' };
        }

        const recentCount = state.promptTimestamps.filter(ts => ts >= cutoff).length;
        const remaining = Math.max(0, this.config.maxPromptsPerWindow - recentCount);

        return {
            fatigued: recentCount > this.config.maxPromptsPerWindow,
            promptCount: recentCount,
            remaining,
            action: recentCount > this.config.maxPromptsPerWindow ? 'deny' : 'allow_prompt',
        };
    }

    /**
     * Reset fatigue state for a user (e.g., after cooldown or admin reset).
     */
    reset(userId: string): void {
        this.states.delete(userId);
    }

    /**
     * Clear all expired states.
     */
    purgeExpired(): number {
        const cutoff = Date.now() - this.config.windowMs;
        let count = 0;
        for (const [id, state] of this.states) {
            const active = state.promptTimestamps.filter(ts => ts >= cutoff);
            if (active.length === 0) {
                this.states.delete(id);
                count++;
            }
        }
        return count;
    }

    getState(userId: string): FatigueState | undefined {
        return this.states.get(userId);
    }

    get trackedUserCount(): number {
        return this.states.size;
    }
}
