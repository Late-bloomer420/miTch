/**
 * shared-types — Runtime validation tests
 *
 * Tests the runtime-callable functions and shape/enum compliance
 * for all 11 type modules. Pure-TypeScript interfaces get shape
 * conformance checks; modules with runtime logic get unit tests.
 *
 * Modules with runtime functions:
 *   - verifier-trust.ts  → calculateTrustScore()
 *   - ad-preferences.ts  → quantizeTimeSlot(), quantizeBudget(), quantizeDayBucket()
 *   - predicates.ts      → canonicalizePredicate(), canonicalizeRequest(), legacyToDSL()
 *                          (covered in predicates.test.ts — smoke-checked here)
 *
 * Enum / union coverage:
 *   - audit.ts           → AuditEventType values
 *   - ad-response.ts     → AdDenyReason values
 *   - oid4vci.ts         → OID4VCIError values, CredentialFormat
 *   - anchor.ts          → AnchorRef provider values
 */

import { describe, it, expect } from 'vitest';

// ── runtime functions ────────────────────────────────────────────────────────

import { calculateTrustScore } from '../src/verifier-trust.js';
import type { VerifierReputation } from '../src/verifier-trust.js';

import {
    quantizeTimeSlot,
    quantizeBudget,
    quantizeDayBucket,
} from '../src/ad-preferences.js';
import type { QuantizedBudgetSignal } from '../src/ad-preferences.js';

// ── enum / union types (imported for shape checks) ───────────────────────────

import type { AuditEventType, AuditLogEntry } from '../src/audit.js';
import type { AdDenyReason, AdVerificationResponse } from '../src/ad-response.js';
import type { OID4VCIError } from '../src/oid4vci.js';
import type { AnchorRef } from '../src/anchor.js';
import type { Result } from '../src/index.js';

// ─── calculateTrustScore ──────────────────────────────────────────────────────

function makeRep(overrides: Partial<VerifierReputation> = {}): VerifierReputation {
    return {
        did: 'did:web:verifier.test',
        successfulTransactions: 0,
        violationReports: 0,
        confirmedViolations: 0,
        trustScore: 0,
        denyListed: false,
        ...overrides,
    };
}

describe('calculateTrustScore — deny-listed', () => {
    it('always returns 0 for deny-listed verifiers', () => {
        const rep = makeRep({ denyListed: true, successfulTransactions: 10000, confirmedViolations: 0 });
        expect(calculateTrustScore(rep)).toBe(0);
    });

    it('deny-listed overrides high transaction count', () => {
        expect(calculateTrustScore(makeRep({ denyListed: true, successfulTransactions: 1_000_000 }))).toBe(0);
    });
});

describe('calculateTrustScore — base (no transactions, no violations)', () => {
    it('returns 50 for a brand-new verifier', () => {
        const score = calculateTrustScore(makeRep({ successfulTransactions: 0, confirmedViolations: 0 }));
        // base 50, volume = log10(1)*5 = 0, penalty = 0/(0+1)*500 = 0 → 50
        expect(score).toBeCloseTo(50, 2);
    });
});

describe('calculateTrustScore — volume bonus', () => {
    it('increases score with more transactions (up to +20)', () => {
        const low = calculateTrustScore(makeRep({ successfulTransactions: 10 }));
        const high = calculateTrustScore(makeRep({ successfulTransactions: 10000 }));
        expect(high).toBeGreaterThan(low);
    });

    it('caps volume bonus at +20 (score cannot exceed 70 from volume alone)', () => {
        const huge = calculateTrustScore(makeRep({ successfulTransactions: 1_000_000_000 }));
        // max = 50 + 20 = 70
        expect(huge).toBeLessThanOrEqual(70);
    });

    it('100 transactions gives meaningful bonus', () => {
        const score = calculateTrustScore(makeRep({ successfulTransactions: 100 }));
        // log10(101)*5 ≈ 10.04 → score ≈ 60
        expect(score).toBeGreaterThan(55);
        expect(score).toBeLessThanOrEqual(70);
    });
});

describe('calculateTrustScore — violation penalty', () => {
    it('violations reduce score', () => {
        const clean = calculateTrustScore(makeRep({ successfulTransactions: 100, confirmedViolations: 0 }));
        const dirty = calculateTrustScore(makeRep({ successfulTransactions: 100, confirmedViolations: 1 }));
        expect(dirty).toBeLessThan(clean);
    });

    it('high violation rate pushes score toward 0', () => {
        // 10 violations / 10 transactions = 100% violation rate → penalty = min(50, 1*500=500) = 50
        const score = calculateTrustScore(makeRep({ successfulTransactions: 10, confirmedViolations: 10 }));
        expect(score).toBeLessThan(10);
    });

    it('score is clamped to minimum 0 (never negative)', () => {
        const score = calculateTrustScore(makeRep({
            successfulTransactions: 1,
            confirmedViolations: 100,
        }));
        expect(score).toBeGreaterThanOrEqual(0);
    });

    it('score is clamped to maximum 100', () => {
        const score = calculateTrustScore(makeRep({ successfulTransactions: 1_000_000 }));
        expect(score).toBeLessThanOrEqual(100);
    });
});

describe('calculateTrustScore — output type', () => {
    it('always returns a finite number', () => {
        for (const tx of [0, 1, 10, 1000]) {
            const s = calculateTrustScore(makeRep({ successfulTransactions: tx }));
            expect(Number.isFinite(s)).toBe(true);
        }
    });
});

// ─── quantizeTimeSlot ─────────────────────────────────────────────────────────

describe('quantizeTimeSlot', () => {
    function makeDate(hour: number): Date {
        const d = new Date('2026-01-01T00:00:00');
        d.setHours(hour, 0, 0, 0);
        return d;
    }

    it('hour 0 → SLOT_NIGHT', () => expect(quantizeTimeSlot(makeDate(0))).toBe('SLOT_NIGHT'));
    it('hour 3 → SLOT_NIGHT', () => expect(quantizeTimeSlot(makeDate(3))).toBe('SLOT_NIGHT'));
    it('hour 5 → SLOT_NIGHT', () => expect(quantizeTimeSlot(makeDate(5))).toBe('SLOT_NIGHT'));
    it('hour 6 → SLOT_MORNING', () => expect(quantizeTimeSlot(makeDate(6))).toBe('SLOT_MORNING'));
    it('hour 8 → SLOT_MORNING', () => expect(quantizeTimeSlot(makeDate(8))).toBe('SLOT_MORNING'));
    it('hour 9 → SLOT_MORNING', () => expect(quantizeTimeSlot(makeDate(9))).toBe('SLOT_MORNING'));
    it('hour 10 → SLOT_MIDDAY', () => expect(quantizeTimeSlot(makeDate(10))).toBe('SLOT_MIDDAY'));
    it('hour 12 → SLOT_MIDDAY', () => expect(quantizeTimeSlot(makeDate(12))).toBe('SLOT_MIDDAY'));
    it('hour 13 → SLOT_MIDDAY', () => expect(quantizeTimeSlot(makeDate(13))).toBe('SLOT_MIDDAY'));
    it('hour 14 → SLOT_AFTERNOON', () => expect(quantizeTimeSlot(makeDate(14))).toBe('SLOT_AFTERNOON'));
    it('hour 17 → SLOT_AFTERNOON', () => expect(quantizeTimeSlot(makeDate(17))).toBe('SLOT_AFTERNOON'));
    it('hour 18 → SLOT_EVENING', () => expect(quantizeTimeSlot(makeDate(18))).toBe('SLOT_EVENING'));
    it('hour 21 → SLOT_EVENING', () => expect(quantizeTimeSlot(makeDate(21))).toBe('SLOT_EVENING'));
    it('hour 22 → SLOT_LATE', () => expect(quantizeTimeSlot(makeDate(22))).toBe('SLOT_LATE'));
    it('hour 23 → SLOT_LATE', () => expect(quantizeTimeSlot(makeDate(23))).toBe('SLOT_LATE'));

    it('covers all 24 hours with exactly 6 distinct buckets', () => {
        const buckets = new Set(
            Array.from({ length: 24 }, (_, h) => quantizeTimeSlot(makeDate(h)))
        );
        expect(buckets.size).toBe(6);
    });
});

// ─── quantizeBudget ───────────────────────────────────────────────────────────

describe('quantizeBudget', () => {
    it('null → BUDGET_UNLIMITED', () => expect(quantizeBudget(null)).toBe('BUDGET_UNLIMITED'));
    it('0 → BUDGET_EXHAUSTED', () => expect(quantizeBudget(0)).toBe('BUDGET_EXHAUSTED'));
    it('1 → BUDGET_LOW', () => expect(quantizeBudget(1)).toBe('BUDGET_LOW'));
    it('5 → BUDGET_LOW', () => expect(quantizeBudget(5)).toBe('BUDGET_LOW'));
    it('6 → BUDGET_MEDIUM', () => expect(quantizeBudget(6)).toBe('BUDGET_MEDIUM'));
    it('15 → BUDGET_MEDIUM', () => expect(quantizeBudget(15)).toBe('BUDGET_MEDIUM'));
    it('16 → BUDGET_HIGH', () => expect(quantizeBudget(16)).toBe('BUDGET_HIGH'));
    it('50 → BUDGET_HIGH', () => expect(quantizeBudget(50)).toBe('BUDGET_HIGH'));
    it('51 → BUDGET_UNLIMITED', () => expect(quantizeBudget(51)).toBe('BUDGET_UNLIMITED'));
    it('1000 → BUDGET_UNLIMITED', () => expect(quantizeBudget(1000)).toBe('BUDGET_UNLIMITED'));

    it('returns 5 distinct buckets across full range', () => {
        const results = new Set([
            quantizeBudget(null),
            quantizeBudget(0),
            quantizeBudget(1),
            quantizeBudget(6),
            quantizeBudget(16),
        ]);
        expect(results.size).toBe(5);
    });
});

// ─── quantizeDayBucket ────────────────────────────────────────────────────────

describe('quantizeDayBucket', () => {
    it('undefined → DAYS_ALL', () => expect(quantizeDayBucket(undefined)).toBe('DAYS_ALL'));
    it('all 7 days → DAYS_ALL', () => {
        expect(quantizeDayBucket(['mon','tue','wed','thu','fri','sat','sun'])).toBe('DAYS_ALL');
    });
    it('weekdays only → DAYS_WEEKDAYS', () => {
        expect(quantizeDayBucket(['mon','tue','wed','thu','fri'])).toBe('DAYS_WEEKDAYS');
    });
    it('weekends only → DAYS_WEEKENDS', () => {
        expect(quantizeDayBucket(['sat','sun'])).toBe('DAYS_WEEKENDS');
    });
    it('custom subset (mon+wed+fri) → DAYS_RESTRICTED', () => {
        expect(quantizeDayBucket(['mon','wed','fri'])).toBe('DAYS_RESTRICTED');
    });
    it('mon+sat (mixed) → DAYS_RESTRICTED', () => {
        expect(quantizeDayBucket(['mon','sat'])).toBe('DAYS_RESTRICTED');
    });
    it('empty array → DAYS_RESTRICTED', () => {
        // 0 days != 7, no weekday/weekend match
        expect(quantizeDayBucket([])).toBe('DAYS_RESTRICTED');
    });
    it('6 days (missing one weekday) → DAYS_RESTRICTED', () => {
        expect(quantizeDayBucket(['mon','tue','wed','thu','sat','sun'])).toBe('DAYS_RESTRICTED');
    });
});

// ─── AuditEventType — enum values ────────────────────────────────────────────

describe('AuditEventType — all event types are valid strings', () => {
    const EXPECTED: AuditEventType[] = [
        'KEY_CREATED', 'KEY_USED', 'KEY_DESTROYED',
        'VC_IMPORTED', 'VC_DELETED',
        'VP_GENERATED', 'VP_SENT',
        'POLICY_EVALUATED', 'POLICY_BLOCKED',
        'USER_CONSENT_GRANTED', 'USER_CONSENT_DENIED',
    ];

    it('all expected event types are non-empty strings', () => {
        for (const t of EXPECTED) {
            expect(typeof t).toBe('string');
            expect(t.length).toBeGreaterThan(0);
        }
    });

    it('11 distinct event types', () => {
        expect(new Set(EXPECTED).size).toBe(11);
    });

    it('AuditLogEntry satisfies shape at runtime', () => {
        const entry: AuditLogEntry = {
            id: 'e-1',
            timestamp: '2026-01-01T00:00:00.000Z',
            action: 'POLICY_EVALUATED',
            verifierId: 'did:web:shop.test',
            dataSubjectId: undefined,
        };
        expect(entry.action).toBe('POLICY_EVALUATED');
        expect(entry.id).toBeTruthy();
    });
});

// ─── AdDenyReason — enum values ───────────────────────────────────────────────

describe('AdDenyReason — all deny reasons are valid strings', () => {
    const EXPECTED_DENY_REASONS = [
        'POLICY_NO_MATCH',
        'PREDICATE_FAILED',
        'CREDENTIAL_MISSING',
        'CATEGORY_DENIED',
        'SCHEDULE_DENIED',
        'QUIET_PERIOD',
        'BUDGET_EXHAUSTED',
        'BINDING_INVALID',
        'REQUEST_EXPIRED',
    ] as const;

    it('all expected deny reasons are non-empty strings', () => {
        for (const r of EXPECTED_DENY_REASONS) {
            expect(typeof r).toBe('string');
            expect(r.length).toBeGreaterThan(0);
        }
    });

    it('9 distinct deny reasons', () => {
        expect(new Set(EXPECTED_DENY_REASONS).size).toBe(9);
    });

    it('AdVerificationResponse with DENY verdict has denyReason', () => {
        const resp: Partial<AdVerificationResponse> = {
            verdict: 'DENY',
            denyReason: 'BUDGET_EXHAUSTED',
        };
        expect(resp.verdict).toBe('DENY');
        expect(resp.denyReason).toBe('BUDGET_EXHAUSTED');
    });

    it('AdVerificationResponse with ALLOW verdict has no denyReason', () => {
        const resp: Partial<AdVerificationResponse> = {
            verdict: 'ALLOW',
        };
        expect(resp.verdict).toBe('ALLOW');
        expect(resp.denyReason).toBeUndefined();
    });
});

// ─── OID4VCIError — enum values ───────────────────────────────────────────────

describe('OID4VCIError — error codes', () => {
    const EXPECTED_ERRORS = [
        'invalid_request',
        'invalid_token',
        'unsupported_credential_type',
        'unsupported_credential_format',
        'invalid_or_missing_proof',
        'invalid_encryption_parameters',
    ] as const;

    it('all OID4VCI error codes are non-empty strings', () => {
        for (const e of EXPECTED_ERRORS) {
            const asType = e as OID4VCIError;
            expect(typeof asType).toBe('string');
        }
    });

    it('6 distinct OID4VCI error codes', () => {
        expect(new Set(EXPECTED_ERRORS).size).toBe(6);
    });
});

// ─── AnchorRef — provider values ──────────────────────────────────────────────

describe('AnchorRef — provider values', () => {
    const PROVIDERS: AnchorRef['provider'][] = [
        'TRANSPARENCY_LOG',
        'PUBLIC_LEDGER',
        'INTERNAL_WORM',
        'DEV_NULL',
    ];

    it('all 4 providers are non-empty strings', () => {
        for (const p of PROVIDERS) {
            expect(typeof p).toBe('string');
            expect(p.length).toBeGreaterThan(0);
        }
    });

    it('AnchorRef object satisfies shape', () => {
        const ref: AnchorRef = {
            provider: 'DEV_NULL',
            batchId: 'batch-001',
            root: 'a'.repeat(64),
            timestamp: '2026-01-01T00:00:00Z',
            txId: undefined,
        };
        expect(ref.provider).toBe('DEV_NULL');
        expect(ref.batchId).toBe('batch-001');
    });
});

// ─── QuantizedBudgetSignal — shape compliance ─────────────────────────────────

describe('QuantizedBudgetSignal — shape compliance', () => {
    it('constructed signal satisfies interface at runtime', () => {
        const signal: QuantizedBudgetSignal = {
            timeSlot: quantizeTimeSlot(new Date()),
            dayBucket: quantizeDayBucket(['mon','tue','wed','thu','fri']),
            scheduleAllowed: true,
            budgetBucket: quantizeBudget(10),
            categoryBucket: 'CATEGORY_STANDARD',
            categoryAllowed: true,
            validUntil: new Date(Date.now() + 60_000).toISOString(),
            quantizationVersion: '1.0',
        };
        expect(signal.quantizationVersion).toBe('1.0');
        expect(signal.dayBucket).toBe('DAYS_WEEKDAYS');
        expect(signal.budgetBucket).toBe('BUDGET_MEDIUM');
    });

    it('scheduleAllowed is a boolean (not undefined)', () => {
        const signal: QuantizedBudgetSignal = {
            timeSlot: 'SLOT_MORNING',
            dayBucket: 'DAYS_ALL',
            scheduleAllowed: false, // quiet period in effect
            budgetBucket: 'BUDGET_HIGH',
            categoryBucket: 'CATEGORY_ALL',
            categoryAllowed: false,
            validUntil: '2026-01-01T00:01:00Z',
            quantizationVersion: '1.0',
        };
        expect(typeof signal.scheduleAllowed).toBe('boolean');
        expect(typeof signal.categoryAllowed).toBe('boolean');
    });
});

// ─── Result<T> — discriminated union narrowing ───────────────────────────────

describe('Result<T> — discriminated union narrowing', () => {
    it('ok:true branch carries value', () => {
        const r: Result<number> = { ok: true, value: 42 };
        if (r.ok) {
            expect(r.value).toBe(42);
        } else {
            throw new Error('Should not reach error branch');
        }
    });

    it('ok:false branch carries error', () => {
        const err = new Error('fail');
        const r: Result<number> = { ok: false, error: err };
        if (!r.ok) {
            expect(r.error).toBe(err);
        } else {
            throw new Error('Should not reach ok branch');
        }
    });

    it('Result<string, string> custom error type narrows correctly', () => {
        const r: Result<string, string> = { ok: false, error: 'NOT_FOUND' };
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toBe('NOT_FOUND');
    });
});
