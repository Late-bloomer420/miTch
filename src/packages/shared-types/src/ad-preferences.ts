/**
 * @module @mitch/shared-types/ad-preferences
 *
 * User-controlled ad preferences and quantized budget signals.
 *
 * Design: Users define granular preferences internally.
 * The wallet quantizes all signals before sending to verifiers
 * to maintain anonymity sets and prevent temporal fingerprinting.
 *
 * See ADR-ADTECH-004 (UserAdPreferences) and ADR-ADTECH-005 (Budget Signal Quantization).
 */

// ---------------------------------------------------------------------------
// User Ad Preferences (full internal detail — never sent to verifier as-is)
// ---------------------------------------------------------------------------

export interface UserAdPreferences {
    version: '1.0';
    limits?: AdLimits;
    schedule?: AdSchedule;
    categories?: AdCategories;
    /** Quiet periods — hidden as scheduleAllowed: false, never exposed directly */
    quietPeriods?: QuietPeriod[];
    /** Per-verifier overrides — blocked verifiers get POLICY_NO_MATCH, indistinguishable from unknown */
    verifierOverrides?: VerifierAdOverride[];
}

export interface AdLimits {
    /** Max impressions per day across all verifiers */
    maxPerDay?: number;
    /** Max impressions per week */
    maxPerWeek?: number;
    /** Max impressions per verifier per day */
    maxPerVerifierPerDay?: number;
    /** Minimum seconds between two impressions */
    minIntervalSeconds?: number;
}

export interface AdSchedule {
    /** Allowed hours window (local time) */
    allowedHours?: { start: number; end: number };
    /** Allowed days of week */
    allowedDays?: ('mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun')[];
    /** IANA timezone string */
    timezone?: string;
}

export interface AdCategories {
    /** IAB category codes to allow (acts as allowlist if set) */
    allowed?: string[];
    /** IAB category codes to deny */
    denied?: string[];
}

export interface QuietPeriod {
    /** ISO 8601 start datetime */
    start: string;
    /** ISO 8601 end datetime */
    end: string;
    /** Internal reason — never transmitted */
    reason?: string;
}

export interface VerifierAdOverride {
    /** Glob pattern matching verifier DID */
    verifierPattern: string;
    limits?: Partial<AdLimits>;
    schedule?: Partial<AdSchedule>;
    /** If true: blocked verifier gets POLICY_NO_MATCH — same as unknown, no leakage */
    blocked?: boolean;
}

// ---------------------------------------------------------------------------
// Quantized signal types (sent to verifier)
// ---------------------------------------------------------------------------

/**
 * 6 time slots covering 24 hours.
 * Internal exact times are mapped to these buckets.
 * Prevents temporal fingerprinting from precise timestamps.
 */
export type TimeSlot =
    | 'SLOT_NIGHT'      // 00:00–06:00
    | 'SLOT_MORNING'    // 06:00–10:00
    | 'SLOT_MIDDAY'     // 10:00–14:00
    | 'SLOT_AFTERNOON'  // 14:00–18:00
    | 'SLOT_EVENING'    // 18:00–22:00
    | 'SLOT_LATE';      // 22:00–00:00

/**
 * 4 day buckets.
 * Custom day subsets are mapped to DAYS_RESTRICTED.
 */
export type DayBucket =
    | 'DAYS_ALL'        // Every day
    | 'DAYS_WEEKDAYS'   // Mon–Fri only
    | 'DAYS_WEEKENDS'   // Sat–Sun only
    | 'DAYS_RESTRICTED'; // Custom subset

/**
 * 5 budget buckets.
 * Exact remaining counts are hidden behind these ranges.
 */
export type BudgetBucket =
    | 'BUDGET_EXHAUSTED'  // 0 remaining
    | 'BUDGET_LOW'        // 1–5 remaining
    | 'BUDGET_MEDIUM'     // 6–15 remaining
    | 'BUDGET_HIGH'       // 16–50 remaining
    | 'BUDGET_UNLIMITED'; // >50 or no limit

/**
 * 4 category policy buckets.
 */
export type CategoryBucket =
    | 'CATEGORY_ALL'        // No restrictions
    | 'CATEGORY_STANDARD'   // Common restrictions (gambling, adult)
    | 'CATEGORY_RESTRICTED' // Multiple categories blocked
    | 'CATEGORY_ALLOWLIST'; // Only specific categories allowed

/**
 * The quantized signal sent to verifiers.
 *
 * 6 × 4 × 5 × 4 = 480 combinations.
 * With binary scheduleAllowed + categoryAllowed: 1,920 possible signals.
 * At 10M users → average anonymity set ~5,200 users per signal.
 *
 * Design rules:
 * - Quiet periods hidden behind scheduleAllowed: false
 * - Blocked verifiers get POLICY_NO_MATCH, not this signal
 * - validUntil: short TTL (60s) to prevent replay
 */
export interface QuantizedBudgetSignal {
    timeSlot: TimeSlot;
    dayBucket: DayBucket;
    /** Is current time within user's allowed schedule? (quiet periods also produce false) */
    scheduleAllowed: boolean;
    budgetBucket: BudgetBucket;
    categoryBucket: CategoryBucket;
    /** Is the requested category allowed? Binary — no category detail leaked */
    categoryAllowed: boolean;
    /** Short-lived validity window (ISO 8601) */
    validUntil: string;
    quantizationVersion: '1.0';
}

// ---------------------------------------------------------------------------
// Quantization functions
// ---------------------------------------------------------------------------

/**
 * Map a Date to a 4-hour time slot bucket.
 * Prevents temporal fingerprinting from exact request times.
 */
export function quantizeTimeSlot(date: Date): TimeSlot {
    const hour = date.getHours();
    if (hour < 6) return 'SLOT_NIGHT';
    if (hour < 10) return 'SLOT_MORNING';
    if (hour < 14) return 'SLOT_MIDDAY';
    if (hour < 18) return 'SLOT_AFTERNOON';
    if (hour < 22) return 'SLOT_EVENING';
    return 'SLOT_LATE';
}

/**
 * Map a remaining impression count to a budget bucket.
 * null means no limit set → BUDGET_UNLIMITED.
 */
export function quantizeBudget(remaining: number | null): BudgetBucket {
    if (remaining === null || remaining > 50) return 'BUDGET_UNLIMITED';
    if (remaining === 0) return 'BUDGET_EXHAUSTED';
    if (remaining <= 5) return 'BUDGET_LOW';
    if (remaining <= 15) return 'BUDGET_MEDIUM';
    return 'BUDGET_HIGH';
}

/**
 * Map an allowed-days array to a day bucket.
 * undefined or full week → DAYS_ALL.
 */
export function quantizeDayBucket(allowedDays?: string[]): DayBucket {
    if (!allowedDays || allowedDays.length === 7) return 'DAYS_ALL';
    const weekdays = ['mon', 'tue', 'wed', 'thu', 'fri'];
    const weekends = ['sat', 'sun'];
    const hasAllWeekdays = weekdays.every(d => allowedDays.includes(d));
    const hasNoWeekends = !weekends.some(d => allowedDays.includes(d));
    if (hasAllWeekdays && hasNoWeekends) return 'DAYS_WEEKDAYS';
    const hasAllWeekends = weekends.every(d => allowedDays.includes(d));
    const hasNoWeekdays = !weekdays.some(d => allowedDays.includes(d));
    if (hasAllWeekends && hasNoWeekdays) return 'DAYS_WEEKENDS';
    return 'DAYS_RESTRICTED';
}
