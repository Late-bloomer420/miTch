/**
 * G-02 — Wallet PWA: PrivacyAuditService Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PrivacyAuditService } from '../services/PrivacyAuditService';

vi.useFakeTimers();

describe('G-02 — PrivacyAuditService.auditTransaction', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    async function runAudit(verifier: string) {
        const promise = PrivacyAuditService.auditTransaction(verifier);
        await vi.runAllTimersAsync();
        return promise;
    }

    it('returns a PrivacyContext with the verifier name', async () => {
        const ctx = await runAudit('Liquor Store GmbH');
        expect(ctx.verifier).toBe('Liquor Store GmbH');
    });

    it('transactionId is a non-empty UUID string', async () => {
        const ctx = await runAudit('test-verifier');
        expect(ctx.transactionId).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
        );
    });

    it('detectedTrackers is a non-empty array', async () => {
        const ctx = await runAudit('test-verifier');
        expect(ctx.detectedTrackers.length).toBeGreaterThan(0);
    });

    it('privacyScore.overall is between 0 and 100', async () => {
        const ctx = await runAudit('test-verifier');
        expect(ctx.privacyScore.overall).toBeGreaterThanOrEqual(0);
        expect(ctx.privacyScore.overall).toBeLessThanOrEqual(100);
    });

    it('userConsent.status is one of the expected values', async () => {
        const ctx = await runAudit('test-verifier');
        expect(['EXPLICIT_ACCEPT', 'REJECT', 'CONDITIONAL_ACCEPT']).toContain(ctx.userConsent.status);
    });

    it('auditProof has hash (64 hex chars) and signature', async () => {
        const ctx = await runAudit('test-verifier');
        expect(ctx.auditProof.hash).toMatch(/^[0-9a-f]{64}$/);
        expect(ctx.auditProof.signature).toBeDefined();
    });

    it('each tracker has required fields', async () => {
        const ctx = await runAudit('test-verifier');
        for (const tracker of ctx.detectedTrackers) {
            expect(tracker.layer).toBeDefined();
            expect(tracker.actor).toBeDefined();
            expect(['LOW', 'MEDIUM', 'HIGH']).toContain(tracker.riskLevel);
            expect(tracker.dataExposed).toBeInstanceOf(Array);
            expect(tracker.mitigations).toBeInstanceOf(Array);
        }
    });

    it('two calls produce different transactionIds', async () => {
        const ctx1 = await runAudit('v1');
        const ctx2 = await runAudit('v2');
        expect(ctx1.transactionId).not.toBe(ctx2.transactionId);
    });

    it('Windows user-agent detected as MEDIUM risk OS', async () => {
        Object.defineProperty(navigator, 'userAgent', {
            value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            configurable: true,
        });
        const ctx = await runAudit('test-windows');
        const osTracker = ctx.detectedTrackers.find(t => t.layer === 'OS');
        expect(osTracker).toBeDefined();
        expect(osTracker!.actor).toBe('Microsoft');
        expect(osTracker!.riskLevel).toBe('MEDIUM');
    });
});
