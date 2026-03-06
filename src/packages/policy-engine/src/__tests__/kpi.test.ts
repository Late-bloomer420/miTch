import { describe, it, expect } from 'vitest';
import { KPIEngine, computeSecurityScore, DEFAULT_ALERT_THRESHOLDS } from '../kpi';

function makeRecord(verdict: 'ALLOW' | 'DENY' | 'PROMPT', reasons: string[] = []) {
    return { verdict, reasons, verifierId: 'v1', timestamp: Date.now() };
}

describe('computeSecurityScore', () => {
    it('returns 50 for zero requests', () => {
        expect(computeSecurityScore({ denyRate: 0, allowRate: 0, totalRequests: 0 })).toBe(50);
    });

    it('penalizes very high allow rate (>95%)', () => {
        const score = computeSecurityScore({ denyRate: 0.02, allowRate: 0.98, totalRequests: 100 });
        expect(score).toBeLessThan(100);
    });

    it('penalizes very high deny rate (>80%)', () => {
        const score = computeSecurityScore({ denyRate: 0.85, allowRate: 0.1, totalRequests: 100 });
        expect(score).toBeLessThan(100);
    });

    it('penalizes high WebAuthn drift', () => {
        const withDrift = computeSecurityScore({ denyRate: 0.1, allowRate: 0.9, totalRequests: 100, webauthnDriftMs: 90_000 });
        const noDrift = computeSecurityScore({ denyRate: 0.1, allowRate: 0.9, totalRequests: 100, webauthnDriftMs: 0 });
        expect(withDrift).toBeLessThan(noDrift);
    });
});

describe('KPIEngine', () => {
    it('starts with empty snapshot', () => {
        const kpi = new KPIEngine();
        const snap = kpi.snapshot();
        expect(snap.totalRequests).toBe(0);
        expect(snap.denyRate).toBe(0);
        expect(snap.softFailActive).toBe(false);
    });

    it('tracks allow/deny/prompt counts', () => {
        const kpi = new KPIEngine();
        kpi.record(makeRecord('ALLOW'));
        kpi.record(makeRecord('ALLOW'));
        kpi.record(makeRecord('DENY', ['DENY_RATE_LIMIT_EXCEEDED']));
        kpi.record(makeRecord('PROMPT'));
        const snap = kpi.snapshot();
        expect(snap.allowCount).toBe(2);
        expect(snap.denyCount).toBe(1);
        expect(snap.promptCount).toBe(1);
        expect(snap.totalRequests).toBe(4);
    });

    it('computes deny rate correctly', () => {
        const kpi = new KPIEngine();
        for (let i = 0; i < 3; i++) kpi.record(makeRecord('DENY'));
        for (let i = 0; i < 7; i++) kpi.record(makeRecord('ALLOW'));
        const snap = kpi.snapshot();
        expect(snap.denyRate).toBeCloseTo(0.3);
        expect(snap.allowRate).toBeCloseTo(0.7);
    });

    it('builds deny category breakdown', () => {
        const kpi = new KPIEngine();
        kpi.record(makeRecord('DENY', ['DENY_CREDENTIAL_REVOKED']));
        kpi.record(makeRecord('DENY', ['DENY_CREDENTIAL_REVOKED']));
        kpi.record(makeRecord('DENY', ['DENY_BINDING_NONCE_REPLAY']));
        const snap = kpi.snapshot();
        expect(snap.denyCategoryBreakdown['DENY_CREDENTIAL_REVOKED']).toBe(2);
        expect(snap.denyCategoryBreakdown['DENY_BINDING_NONCE_REPLAY']).toBe(1);
    });

    it('triggers critical alert at high deny rate', () => {
        const kpi = new KPIEngine();
        for (let i = 0; i < 70; i++) kpi.record(makeRecord('DENY'));
        for (let i = 0; i < 30; i++) kpi.record(makeRecord('ALLOW'));
        const snap = kpi.snapshot();
        expect(snap.alertsTriggered.some(a => a.startsWith('CRITICAL:deny_rate'))).toBe(true);
    });

    it('computes estimated cost', () => {
        const kpi = new KPIEngine();
        for (let i = 0; i < 10; i++) kpi.record(makeRecord('ALLOW'));
        const snap = kpi.snapshot();
        expect(snap.estimatedCostEur).toBeCloseTo(0.01);
    });

    it('activates and deactivates soft-fail mode', () => {
        const kpi = new KPIEngine();
        expect(kpi.isSoftFailActive()).toBe(false);
        kpi.activateSoftFail('test outage');
        expect(kpi.isSoftFailActive()).toBe(true);
        kpi.deactivateSoftFail();
        expect(kpi.isSoftFailActive()).toBe(false);
    });

    it('soft-fail config reflects reason', () => {
        const kpi = new KPIEngine();
        kpi.activateSoftFail('upstream failure');
        expect(kpi.getSoftFailConfig().reason).toBe('upstream failure');
    });

    it('clears records', () => {
        const kpi = new KPIEngine();
        kpi.record(makeRecord('ALLOW'));
        kpi.clearRecords();
        expect(kpi.recordCount).toBe(0);
    });
});
