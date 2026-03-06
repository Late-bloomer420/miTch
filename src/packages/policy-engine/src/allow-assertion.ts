/**
 * Spec 90 — No Silent Allow
 * Spec 91 — False-Allow Zero Tolerance
 *
 * Every ALLOW verdict must be explicitly grounded in an auditable reason.
 * This module provides assertion utilities to enforce this invariant.
 *
 * Invariant: no code path can produce ALLOW without an explicit PolicyRule match.
 */

import type { DecisionCapsule } from '@mitch/shared-types';

// ─── Allow Evidence ────────────────────────────────────────────────

export interface AllowEvidence {
    /** The policy rule ID that authorized this allow */
    ruleId: string;
    /** Human-readable reason */
    reason: string;
    /** Verified verifier fingerprint (if required) */
    verifierFingerprintVerified?: boolean;
    /** Pairwise DID generated */
    pairwiseDIDGenerated?: boolean;
    /** Timestamp of evidence capture */
    evidenceAt: number;
}

export type AllowAssertionResult =
    | { valid: true; evidence: AllowEvidence }
    | { valid: false; violation: string; code: string };

// ─── Allow Assertion Registry ──────────────────────────────────────

/**
 * Validates that an ALLOW decision has auditable evidence.
 * Throws or returns false if the allow cannot be grounded.
 *
 * This is a fail-safe — if called without valid evidence, it forces a re-evaluation.
 */
export function assertAllowIsGrounded(
    capsule: Pick<DecisionCapsule, 'verdict' | 'decision_id' | 'policy_hash'>,
    evidence: Partial<AllowEvidence> | undefined
): AllowAssertionResult {
    if (capsule.verdict !== 'ALLOW') {
        // Not an ALLOW — assertion doesn't apply
        return {
            valid: true,
            evidence: {
                ruleId: 'N/A',
                reason: `Verdict is ${capsule.verdict}, not ALLOW`,
                evidenceAt: Date.now(),
            },
        };
    }

    if (!evidence) {
        return {
            valid: false,
            violation: `ALLOW verdict ${capsule.decision_id} has no evidence`,
            code: 'ALLOW_WITHOUT_EVIDENCE',
        };
    }

    if (!evidence.ruleId || evidence.ruleId.trim() === '') {
        return {
            valid: false,
            violation: `ALLOW verdict ${capsule.decision_id} has empty ruleId`,
            code: 'ALLOW_WITHOUT_RULE',
        };
    }

    if (!evidence.reason || evidence.reason.trim() === '') {
        return {
            valid: false,
            violation: `ALLOW verdict ${capsule.decision_id} has no reason`,
            code: 'ALLOW_WITHOUT_REASON',
        };
    }

    if (!capsule.policy_hash) {
        return {
            valid: false,
            violation: `ALLOW verdict ${capsule.decision_id} lacks policy_hash`,
            code: 'ALLOW_WITHOUT_MANIFEST',
        };
    }

    return {
        valid: true,
        evidence: {
            ruleId: evidence.ruleId,
            reason: evidence.reason,
            verifierFingerprintVerified: evidence.verifierFingerprintVerified ?? false,
            pairwiseDIDGenerated: evidence.pairwiseDIDGenerated ?? false,
            evidenceAt: evidence.evidenceAt ?? Date.now(),
        },
    };
}

// ─── Allow Rate Guard ──────────────────────────────────────────────

export interface AllowRateGuardConfig {
    /** Maximum allow rate (0-1) before alert (default: 0.95) */
    maxAllowRate: number;
    /** Window for rate calculation (ms) */
    windowMs: number;
}

/**
 * Tracks allow rate and alerts if suspiciously high (Spec 91 — False-Allow Zero Tolerance).
 * A very high allow rate might indicate a bug where ALLOW is produced without policy checks.
 */
export class AllowRateGuard {
    private readonly decisions: Array<{ verdict: string; timestamp: number }> = [];
    private readonly config: AllowRateGuardConfig;

    constructor(config: Partial<AllowRateGuardConfig> = {}) {
        this.config = {
            maxAllowRate: 0.95,
            windowMs: 5 * 60 * 1000,
            ...config,
        };
    }

    record(verdict: 'ALLOW' | 'DENY' | 'PROMPT'): void {
        const now = Date.now();
        this.decisions.push({ verdict, timestamp: now });
        this.prune();
    }

    check(): { suspicious: boolean; allowRate: number; message?: string } {
        this.prune();
        const total = this.decisions.length;
        if (total < 10) return { suspicious: false, allowRate: 0 }; // Not enough data

        const allows = this.decisions.filter(d => d.verdict === 'ALLOW').length;
        const allowRate = allows / total;

        if (allowRate > this.config.maxAllowRate) {
            return {
                suspicious: true,
                allowRate,
                message: `SUSPICIOUS: allow rate ${(allowRate * 100).toFixed(1)}% exceeds ${(this.config.maxAllowRate * 100).toFixed(1)}% threshold`,
            };
        }

        return { suspicious: false, allowRate };
    }

    private prune(): void {
        const cutoff = Date.now() - this.config.windowMs;
        let i = 0;
        while (i < this.decisions.length && this.decisions[i].timestamp < cutoff) i++;
        this.decisions.splice(0, i);
    }

    get decisionCount(): number {
        return this.decisions.length;
    }
}
