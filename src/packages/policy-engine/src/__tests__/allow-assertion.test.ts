import { describe, it, expect } from 'vitest';
import { assertAllowIsGrounded, AllowRateGuard } from '../allow-assertion';

describe('assertAllowIsGrounded', () => {
    const allowCapsule = {
        verdict: 'ALLOW' as const,
        decision_id: 'dec-001',
        policy_hash: 'manifest-v1',
    };

    it('passes for valid ALLOW with evidence', () => {
        const r = assertAllowIsGrounded(allowCapsule, {
            ruleId: 'rule-age-check',
            reason: 'Matched rule: age_verification',
            evidenceAt: Date.now(),
        });
        expect(r.valid).toBe(true);
        if (r.valid) expect(r.evidence.ruleId).toBe('rule-age-check');
    });

    it('fails for ALLOW with no evidence', () => {
        const r = assertAllowIsGrounded(allowCapsule, undefined);
        expect(r.valid).toBe(false);
        if (!r.valid) expect(r.code).toBe('ALLOW_WITHOUT_EVIDENCE');
    });

    it('fails for ALLOW with empty ruleId', () => {
        const r = assertAllowIsGrounded(allowCapsule, {
            ruleId: '',
            reason: 'some reason',
            evidenceAt: Date.now(),
        });
        expect(r.valid).toBe(false);
        if (!r.valid) expect(r.code).toBe('ALLOW_WITHOUT_RULE');
    });

    it('fails for ALLOW with empty reason', () => {
        const r = assertAllowIsGrounded(allowCapsule, {
            ruleId: 'rule-1',
            reason: '',
            evidenceAt: Date.now(),
        });
        expect(r.valid).toBe(false);
        if (!r.valid) expect(r.code).toBe('ALLOW_WITHOUT_REASON');
    });

    it('fails for ALLOW without policy_hash', () => {
        const r = assertAllowIsGrounded(
            { verdict: 'ALLOW', decision_id: 'dec-002', policy_hash: '' },
            { ruleId: 'r1', reason: 'ok', evidenceAt: Date.now() }
        );
        expect(r.valid).toBe(false);
        if (!r.valid) expect(r.code).toBe('ALLOW_WITHOUT_MANIFEST');
    });

    it('skips assertion for DENY verdict', () => {
        const r = assertAllowIsGrounded(
            { verdict: 'DENY', decision_id: 'dec-003', policy_hash: 'm1' },
            undefined
        );
        expect(r.valid).toBe(true);
    });

    it('skips assertion for PROMPT verdict', () => {
        const r = assertAllowIsGrounded(
            { verdict: 'PROMPT', decision_id: 'dec-004', policy_hash: 'm1' },
            undefined
        );
        expect(r.valid).toBe(true);
    });
});

describe('AllowRateGuard', () => {
    it('not suspicious with fewer than 10 decisions', () => {
        const guard = new AllowRateGuard({ maxAllowRate: 0.95 });
        for (let i = 0; i < 5; i++) guard.record('ALLOW');
        const r = guard.check();
        expect(r.suspicious).toBe(false);
    });

    it('flags suspicious when all decisions are ALLOW', () => {
        const guard = new AllowRateGuard({ maxAllowRate: 0.9 });
        for (let i = 0; i < 15; i++) guard.record('ALLOW');
        const r = guard.check();
        expect(r.suspicious).toBe(true);
        expect(r.allowRate).toBeCloseTo(1.0);
        expect(r.message).toContain('SUSPICIOUS');
    });

    it('not suspicious with balanced allow/deny', () => {
        const guard = new AllowRateGuard({ maxAllowRate: 0.95 });
        for (let i = 0; i < 10; i++) guard.record('ALLOW');
        for (let i = 0; i < 10; i++) guard.record('DENY');
        const r = guard.check();
        expect(r.suspicious).toBe(false);
        expect(r.allowRate).toBeCloseTo(0.5);
    });
});
