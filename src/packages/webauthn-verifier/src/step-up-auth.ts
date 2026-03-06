/**
 * Spec 67 — Strong Re-Auth Scaffold v1 (WebAuthn Hook)
 *
 * Step-up authentication trigger, re-auth window management, session binding.
 * Designed to integrate with the policy-engine consent flow.
 */

import { randomBytes } from 'crypto';

// ─── Session Binding ───────────────────────────────────────────────

export interface AuthSession {
    sessionId: string;
    userDID: string;
    credentialId: string;
    authenticatedAt: number;
    /** Re-auth required after this timestamp */
    reAuthRequiredAt: number;
    /** Bound to request context (nonce) */
    boundNonce: string;
    stepUpCompleted: boolean;
}

export interface StepUpTrigger {
    reason: 'HIGH_SENSITIVITY' | 'POLICY_REQUIRES_STEP_UP' | 'SESSION_AGING' | 'RISK_SCORE_ELEVATED';
    requiredAssuranceLevel: 'hardware_key' | 'biometric' | 'any';
    timeoutMs: number;
}

export interface StepUpResult {
    granted: boolean;
    sessionId?: string;
    reason?: string;
    completedAt?: number;
}

// ─── Step-Up Auth Manager ─────────────────────────────────────────

const DEFAULT_SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes
const DEFAULT_STEP_UP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes for re-auth

export class StepUpAuthManager {
    private sessions = new Map<string, AuthSession>();
    private pendingStepUps = new Map<string, { trigger: StepUpTrigger; createdAt: number }>();
    private readonly sessionTtlMs: number;

    constructor(sessionTtlMs = DEFAULT_SESSION_TTL_MS) {
        this.sessionTtlMs = sessionTtlMs;
    }

    /**
     * Create a new authenticated session after successful WebAuthn assertion.
     */
    createSession(opts: {
        userDID: string;
        credentialId: string;
        boundNonce: string;
        highSensitivity?: boolean;
    }): AuthSession {
        const sessionId = randomBytes(16).toString('hex');
        const now = Date.now();

        const session: AuthSession = {
            sessionId,
            userDID: opts.userDID,
            credentialId: opts.credentialId,
            authenticatedAt: now,
            reAuthRequiredAt: now + this.sessionTtlMs,
            boundNonce: opts.boundNonce,
            stepUpCompleted: false,
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    /**
     * Determine if step-up authentication is required for a given operation.
     */
    evaluateStepUp(
        sessionId: string,
        operationSensitivity: 'low' | 'medium' | 'high' | 'critical'
    ): { required: boolean; trigger?: StepUpTrigger } {
        const session = this.sessions.get(sessionId);

        if (!session) {
            return {
                required: true,
                trigger: {
                    reason: 'POLICY_REQUIRES_STEP_UP',
                    requiredAssuranceLevel: 'hardware_key',
                    timeoutMs: DEFAULT_STEP_UP_WINDOW_MS,
                },
            };
        }

        const now = Date.now();

        // Check session aging
        if (now > session.reAuthRequiredAt) {
            return {
                required: true,
                trigger: {
                    reason: 'SESSION_AGING',
                    requiredAssuranceLevel: 'any',
                    timeoutMs: DEFAULT_STEP_UP_WINDOW_MS,
                },
            };
        }

        // High/critical operations always require step-up unless already completed
        if ((operationSensitivity === 'high' || operationSensitivity === 'critical') && !session.stepUpCompleted) {
            return {
                required: true,
                trigger: {
                    reason: 'HIGH_SENSITIVITY',
                    requiredAssuranceLevel: operationSensitivity === 'critical' ? 'biometric' : 'hardware_key',
                    timeoutMs: DEFAULT_STEP_UP_WINDOW_MS,
                },
            };
        }

        return { required: false };
    }

    /**
     * Complete a step-up authentication for a session.
     * Called after WebAuthn assertion is verified.
     */
    completeStepUp(sessionId: string): StepUpResult {
        const session = this.sessions.get(sessionId);

        if (!session) {
            return { granted: false, reason: 'SESSION_NOT_FOUND' };
        }

        if (Date.now() > session.reAuthRequiredAt + 5 * 60 * 1000) {
            this.sessions.delete(sessionId);
            return { granted: false, reason: 'STEP_UP_TIMEOUT' };
        }

        // Extend session and mark step-up completed
        session.stepUpCompleted = true;
        session.reAuthRequiredAt = Date.now() + this.sessionTtlMs;
        this.sessions.set(sessionId, session);

        return { granted: true, sessionId, completedAt: Date.now() };
    }

    /**
     * Validate session is still valid for a given nonce (session binding).
     * Prevents session fixation attacks.
     */
    validateSessionBinding(sessionId: string, nonce: string): boolean {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        if (Date.now() > session.reAuthRequiredAt) return false;
        return session.boundNonce === nonce;
    }

    /**
     * Revoke a session (logout or security event).
     */
    revokeSession(sessionId: string): void {
        this.sessions.delete(sessionId);
    }

    /**
     * Purge expired sessions.
     */
    purgeExpired(): number {
        const now = Date.now();
        let count = 0;
        for (const [id, session] of this.sessions) {
            if (now > session.reAuthRequiredAt) {
                this.sessions.delete(id);
                count++;
            }
        }
        return count;
    }

    get sessionCount(): number {
        return this.sessions.size;
    }

    getSession(sessionId: string): AuthSession | undefined {
        return this.sessions.get(sessionId);
    }
}
