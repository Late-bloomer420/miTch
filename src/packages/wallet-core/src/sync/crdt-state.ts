/**
 * @module @mitch/wallet-core/sync/crdt-state
 *
 * CRDT G-Counter state for multi-device ad budget synchronisation.
 *
 * Design (ADR-ADTECH-006):
 * - Each device has its own counter that only grows (G-Counter)
 * - Merge = take maximum per device (conflict-free, mathematically proven)
 * - Total budget used = sum of all device counters
 * - No central authority — devices sync via neutral encrypted storage
 *
 * Privacy:
 * - State is encrypted before leaving the device (sync key derived from credential)
 * - Storage provider (iCloud, Drive, IPFS) sees only encrypted noise
 *
 * Soft budget principle: Budget is guidance, not hard enforcement.
 * Verifier has the real lever (counts against nullifier).
 * Small over-delivery (1-2 ads) is acceptable during sync window.
 */

// ---------------------------------------------------------------------------
// State structure
// ---------------------------------------------------------------------------

/**
 * CRDT G-Counter state for ad impression budget.
 *
 * Each device increments only its own counter.
 * Global total = sum of all counters.
 * Merge resolves conflicts by taking max per device.
 */
export interface AdImpressionState {
    version: '1.0';
    /**
     * Per-device impression counts.
     * Key: stable device identifier (derived from wallet install, not device ID)
     * Value: impressions shown on this device since last reset
     */
    counters: Record<string, number>;
    /** User's daily impression limit */
    dailyLimit: number;
    /**
     * UTC timestamp when counters reset to zero.
     * ISO 8601, midnight in user's timezone.
     */
    resetAt: string;
    /** Last successful sync timestamp per device */
    lastSync: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/**
 * Calculate remaining budget from CRDT state.
 * Returns 0 if all impressions are used (never negative).
 */
export function calculateRemaining(state: AdImpressionState): number {
    const total = Object.values(state.counters).reduce((a, b) => a + b, 0);
    return Math.max(0, state.dailyLimit - total);
}

/**
 * Increment this device's counter and return updated state.
 * Only call after an ad is actually shown.
 */
export function recordImpression(state: AdImpressionState, deviceId: string): AdImpressionState {
    return {
        ...state,
        counters: {
            ...state.counters,
            [deviceId]: (state.counters[deviceId] ?? 0) + 1,
        },
    };
}

/**
 * Merge two CRDT states (conflict-free).
 *
 * Algorithm: for each device, take the maximum counter value.
 * This ensures no impression is ever "un-counted" during a merge.
 *
 * Example:
 *   Device A: { "A": 3, "B": 1 }  (concurrent)
 *   Device B: { "A": 2, "B": 2 }  (concurrent)
 *   Merged:   { "A": 3, "B": 2 }  ✓ correct total = 5
 */
export function mergeStates(
    local: AdImpressionState,
    remote: AdImpressionState
): AdImpressionState {
    const allDevices = new Set([
        ...Object.keys(local.counters),
        ...Object.keys(remote.counters),
    ]);

    const counters: Record<string, number> = {};
    const lastSync: Record<string, string> = {};

    for (const deviceId of allDevices) {
        // CRDT merge: take maximum (counters only grow)
        counters[deviceId] = Math.max(
            local.counters[deviceId] ?? 0,
            remote.counters[deviceId] ?? 0
        );
        // Keep most recent sync timestamp
        const localSync = local.lastSync[deviceId] ?? '';
        const remoteSync = remote.lastSync[deviceId] ?? '';
        lastSync[deviceId] = localSync > remoteSync ? localSync : remoteSync;
    }

    return {
        version: '1.0',
        counters,
        // Take larger daily limit (in case user changed it on one device)
        dailyLimit: Math.max(local.dailyLimit, remote.dailyLimit),
        // Take later reset time
        resetAt: local.resetAt > remote.resetAt ? local.resetAt : remote.resetAt,
        lastSync,
    };
}

/**
 * Check if the state needs to be reset (daily limit has passed midnight).
 */
export function needsReset(state: AdImpressionState, now: Date = new Date()): boolean {
    return now.toISOString() >= state.resetAt;
}

/**
 * Reset all counters to zero (call at midnight in user's timezone).
 * Preserves daily limit and computes next reset time.
 */
export function resetCounters(
    state: AdImpressionState,
    deviceId: string,
    nextResetAt: string
): AdImpressionState {
    return {
        version: '1.0',
        counters: {},
        dailyLimit: state.dailyLimit,
        resetAt: nextResetAt,
        lastSync: {
            ...state.lastSync,
            [deviceId]: new Date().toISOString(),
        },
    };
}

/**
 * Create a fresh initial state for a new device or new user.
 */
export function createInitialState(dailyLimit: number, resetAt: string): AdImpressionState {
    return {
        version: '1.0',
        counters: {},
        dailyLimit,
        resetAt,
        lastSync: {},
    };
}
