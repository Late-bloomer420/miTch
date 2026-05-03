import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { hasStrongRecentReAuth, resetReAuthState } from '../api/reAuth';

// Mock webauthnVerifier so we can control assertionOk without a real WebAuthn implementation
vi.mock('../api/webauthnVerifier', () => ({
    verifyWebauthnEvidence: vi.fn(() => true),
}));

import { verifyWebauthnEvidence } from '../api/webauthnVerifier';

const validMeta = {
    reAuthRecent: true,
    reAuthMethod: 'webauthn' as const,
    reAuthAssertion: 'base64-assertion-data',
    reAuthChallenge: 'challenge-abc',
    reAuthIssuedAt: new Date().toISOString(),
    reAuthRpId: 'example.com',
    reAuthOrigin: 'https://example.com',
};

beforeEach(() => {
    resetReAuthState();
    vi.clearAllMocks();
    vi.unstubAllEnvs();
});

afterEach(() => {
    vi.unstubAllEnvs();
});

describe('hasStrongRecentReAuth() — REQUIRE_STRONG_REAUTH not set', () => {
    it('returns { ok: true } when reAuthRecent is true and strong reauth is not required', () => {
        const result = hasStrongRecentReAuth({ reAuthRecent: true });
        expect(result.ok).toBe(true);
    });

    it('returns { ok: false } when reAuthRecent is false and strong reauth is not required', () => {
        const result = hasStrongRecentReAuth({ reAuthRecent: false });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when meta is undefined', () => {
        const result = hasStrongRecentReAuth(undefined);
        expect(result.ok).toBe(false);
    });
});

describe('hasStrongRecentReAuth() — REQUIRE_STRONG_REAUTH=1', () => {
    beforeEach(() => {
        vi.stubEnv('REQUIRE_STRONG_REAUTH', '1');
        vi.stubEnv('WEBAUTHN_CHALLENGE_ALLOWLIST', 'challenge-abc,challenge-xyz');
        vi.stubEnv('WEBAUTHN_RPID_ALLOWLIST', 'example.com');
        vi.stubEnv('WEBAUTHN_ORIGIN_ALLOWLIST', 'https://example.com');
        vi.stubEnv('WEBAUTHN_MAX_AGE_SECONDS', '120');
    });

    it('returns { ok: false } when no meta is provided', () => {
        const result = hasStrongRecentReAuth(undefined);
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when reAuthMethod and reAuthAssertion are both absent', () => {
        const result = hasStrongRecentReAuth({ reAuthRecent: true });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when reAuthMethod is not webauthn', () => {
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthMethod: 'other' as any });
        expect(result.ok).toBe(false);
        expect(result.invalidEvidence).toBe(true);
    });

    it('returns { ok: false } when reAuthAssertion is empty string', () => {
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthAssertion: '   ' });
        expect(result.ok).toBe(false);
        expect(result.invalidEvidence).toBe(true);
    });

    it('returns { ok: false } when required fields are missing', () => {
        const result = hasStrongRecentReAuth({
            reAuthMethod: 'webauthn',
            reAuthAssertion: 'some-assertion',
            // Missing: reAuthChallenge, reAuthIssuedAt, reAuthRpId, reAuthOrigin
        });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when reAuthIssuedAt is not a valid date', () => {
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthIssuedAt: 'not-a-date' });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when assertion is too old', () => {
        vi.stubEnv('WEBAUTHN_MAX_AGE_SECONDS', '10');
        const oldIssuedAt = new Date(Date.now() - 30_000).toISOString();
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthIssuedAt: oldIssuedAt });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when challenge is not in allowlist', () => {
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthChallenge: 'unlisted-challenge' });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when rpId is not in allowlist', () => {
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthRpId: 'evil.com' });
        expect(result.ok).toBe(false);
    });

    it('returns { ok: false } when origin is not in allowlist', () => {
        const result = hasStrongRecentReAuth({ ...validMeta, reAuthOrigin: 'https://evil.com' });
        expect(result.ok).toBe(false);
    });

    it('blocks replay: second use of same challenge returns { ok: false }', () => {
        // First use: succeeds
        hasStrongRecentReAuth(validMeta);
        // Second use: replay blocked
        const result = hasStrongRecentReAuth(validMeta);
        expect(result.ok).toBe(false);
        expect(result.invalidEvidence).toBe(true);
    });

    it('different challenges can each be used once', () => {
        const meta1 = { ...validMeta, reAuthChallenge: 'challenge-abc' };
        const meta2 = { ...validMeta, reAuthChallenge: 'challenge-xyz' };

        const r1 = hasStrongRecentReAuth(meta1);
        const r2 = hasStrongRecentReAuth(meta2);
        expect(r1.ok).toBe(true);
        expect(r2.ok).toBe(true);
    });

    it('resetReAuthState() clears used challenges so they can be reused', () => {
        hasStrongRecentReAuth(validMeta);
        resetReAuthState();
        const result = hasStrongRecentReAuth(validMeta);
        expect(result.ok).toBe(true);
    });

    it('returns { ok: false } when verifyWebauthnEvidence returns false', () => {
        vi.mocked(verifyWebauthnEvidence).mockReturnValueOnce(false);
        const result = hasStrongRecentReAuth(validMeta);
        expect(result.ok).toBe(false);
    });
});
