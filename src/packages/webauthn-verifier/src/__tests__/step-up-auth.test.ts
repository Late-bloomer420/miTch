import { describe, it, expect } from 'vitest';
import { StepUpAuthManager } from '../step-up-auth';

describe('StepUpAuthManager', () => {
    it('creates a session with correct fields', () => {
        const mgr = new StepUpAuthManager();
        const session = mgr.createSession({
            userDID: 'did:example:alice',
            credentialId: 'cred-123',
            boundNonce: 'nonce-abc',
        });
        expect(session.userDID).toBe('did:example:alice');
        expect(session.boundNonce).toBe('nonce-abc');
        expect(session.stepUpCompleted).toBe(false);
        expect(session.sessionId).toBeTruthy();
    });

    it('evaluateStepUp returns not required for low-sensitivity in fresh session', () => {
        const mgr = new StepUpAuthManager(60_000);
        const session = mgr.createSession({ userDID: 'u1', credentialId: 'c1', boundNonce: 'n1' });
        const result = mgr.evaluateStepUp(session.sessionId, 'low');
        expect(result.required).toBe(false);
    });

    it('evaluateStepUp requires step-up for high sensitivity', () => {
        const mgr = new StepUpAuthManager(60_000);
        const session = mgr.createSession({ userDID: 'u2', credentialId: 'c2', boundNonce: 'n2' });
        const result = mgr.evaluateStepUp(session.sessionId, 'high');
        expect(result.required).toBe(true);
        expect(result.trigger?.reason).toBe('HIGH_SENSITIVITY');
    });

    it('evaluateStepUp requires step-up for unknown session', () => {
        const mgr = new StepUpAuthManager();
        const result = mgr.evaluateStepUp('nonexistent', 'low');
        expect(result.required).toBe(true);
    });

    it('completeStepUp marks session step-up completed', () => {
        const mgr = new StepUpAuthManager(60_000);
        const session = mgr.createSession({ userDID: 'u3', credentialId: 'c3', boundNonce: 'n3' });
        const result = mgr.completeStepUp(session.sessionId);
        expect(result.granted).toBe(true);
        expect(mgr.getSession(session.sessionId)?.stepUpCompleted).toBe(true);
    });

    it('completeStepUp fails for non-existent session', () => {
        const mgr = new StepUpAuthManager();
        const result = mgr.completeStepUp('ghost-session');
        expect(result.granted).toBe(false);
        expect(result.reason).toBe('SESSION_NOT_FOUND');
    });

    it('validateSessionBinding rejects wrong nonce', () => {
        const mgr = new StepUpAuthManager(60_000);
        const session = mgr.createSession({ userDID: 'u4', credentialId: 'c4', boundNonce: 'correct-nonce' });
        expect(mgr.validateSessionBinding(session.sessionId, 'wrong-nonce')).toBe(false);
        expect(mgr.validateSessionBinding(session.sessionId, 'correct-nonce')).toBe(true);
    });

    it('revokeSession removes session', () => {
        const mgr = new StepUpAuthManager(60_000);
        const session = mgr.createSession({ userDID: 'u5', credentialId: 'c5', boundNonce: 'n5' });
        mgr.revokeSession(session.sessionId);
        expect(mgr.getSession(session.sessionId)).toBeUndefined();
    });

    it('purgeExpired removes timed-out sessions', async () => {
        const mgr = new StepUpAuthManager(1); // 1ms TTL
        mgr.createSession({ userDID: 'u6', credentialId: 'c6', boundNonce: 'n6' });
        await new Promise(r => setTimeout(r, 10));
        const purged = mgr.purgeExpired();
        expect(purged).toBeGreaterThanOrEqual(1);
    });

    it('high-sensitivity after step-up is completed: no longer required', () => {
        const mgr = new StepUpAuthManager(60_000);
        const session = mgr.createSession({ userDID: 'u7', credentialId: 'c7', boundNonce: 'n7' });
        mgr.completeStepUp(session.sessionId);
        const result = mgr.evaluateStepUp(session.sessionId, 'high');
        expect(result.required).toBe(false);
    });
});
