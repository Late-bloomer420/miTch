/**
 * KPI snapshot tests — mock the filesystem so tests run without real event data.
 * The fs mock intercepts readFileSync / existsSync for the events.jsonl path.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── fs mock — must be declared before importing kpi ───────────────────────────
vi.mock('fs', async (importOriginal) => {
    const real = await importOriginal<typeof import('fs')>();
    return {
        ...real,
        existsSync: vi.fn(() => false),
        readFileSync: vi.fn(() => ''),
    };
});

// ── telemetry mocks (imported by kpi.ts) ──────────────────────────────────────
vi.mock('../proof/credentialStatus', () => ({
    getCredentialStatusCacheMetrics: () => ({
        revoked_cache_hit_total: 0,
        revoked_cache_store_total: 0,
    }),
}));

vi.mock('../proof/httpKeySource', () => ({
    getResolverTelemetry: () => ({
        resolver_queries_total: 0,
        resolver_quorum_failures_total: 0,
        resolver_inconsistent_responses_total: 0,
    }),
}));

vi.mock('../api/webauthnVerifier', () => ({
    getWebauthnTelemetry: () => ({
        webauthn_native_attempt_total: 0,
        webauthn_native_success_total: 0,
        webauthn_native_deny_total: 0,
    }),
}));

import { getKpiSnapshot } from '../api/kpi';
import { existsSync, readFileSync } from 'fs';

const mockExistsSync = existsSync as ReturnType<typeof vi.fn>;
const mockReadFileSync = readFileSync as ReturnType<typeof vi.fn>;

function setEvents(lines: object[]): void {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(lines.map(l => JSON.stringify(l)).join('\n'));
}

beforeEach(() => {
    mockExistsSync.mockReturnValue(false);
    mockReadFileSync.mockReturnValue('');
    // Clear env vars that affect the score
    delete process.env.REQUIRE_STRONG_REAUTH;
    delete process.env.WEBAUTHN_VERIFY_MODE;
    delete process.env.WEBAUTHN_ASSERTION_HMAC_SECRET;
    delete process.env.WEBAUTHN_NATIVE_ADAPTER_SECRET;
    delete process.env.ESTIMATED_COST_PER_VERIFICATION_EUR;
    delete process.env.ESTIMATED_MONTHLY_VERIFICATION_VOLUME;
    delete process.env.ESTIMATED_FIXED_MONTHLY_COST_EUR;
    delete process.env.ALLOWED_ALGS;
});

afterEach(() => {
    vi.clearAllMocks();
});

describe('getKpiSnapshot — empty events', () => {
    it('returns zero for decision counts', () => {
        const snap = getKpiSnapshot();
        expect(snap.decisions_total).toBe(0);
        expect(snap.allow_total).toBe(0);
        expect(snap.deny_total).toBe(0);
    });

    it('success rate is 0 when no decisions', () => {
        const snap = getKpiSnapshot();
        expect(snap.verification_success_rate).toBe(0);
    });

    it('replay_block_rate is 1 (no replays = perfect)', () => {
        const snap = getKpiSnapshot();
        expect(snap.replay_block_rate).toBe(1);
    });

    it('false_deny_rate is 0', () => {
        const snap = getKpiSnapshot();
        expect(snap.false_deny_rate).toBe(0);
    });

    it('latency percentiles are 0', () => {
        const snap = getKpiSnapshot();
        expect(snap.latency_p50_ms).toBe(0);
        expect(snap.latency_p95_ms).toBe(0);
    });

    it('security_profile_score is a number in [0, 100]', () => {
        const snap = getKpiSnapshot();
        expect(snap.security_profile_score).toBeGreaterThanOrEqual(0);
        expect(snap.security_profile_score).toBeLessThanOrEqual(100);
    });

    it('all cache/resolver metrics are 0', () => {
        const snap = getKpiSnapshot();
        expect(snap.revoked_cache_hit_total).toBe(0);
        expect(snap.revoked_cache_store_total).toBe(0);
        expect(snap.resolver_queries_total).toBe(0);
        expect(snap.resolver_quorum_failures_total).toBe(0);
    });
});

describe('getKpiSnapshot — decision events', () => {
    it('counts allow and deny decisions', () => {
        setEvents([
            { eventType: 'decision_made', decision: 'ALLOW', latencyMs: 10 },
            { eventType: 'decision_made', decision: 'ALLOW', latencyMs: 20 },
            { eventType: 'decision_made', decision: 'DENY', decisionCode: 'DENY_CREDENTIAL_REVOKED', latencyMs: 5 },
        ]);
        const snap = getKpiSnapshot();
        expect(snap.decisions_total).toBe(3);
        expect(snap.allow_total).toBe(2);
        expect(snap.deny_total).toBe(1);
    });

    it('success rate is correct', () => {
        setEvents([
            { eventType: 'decision_made', decision: 'ALLOW' },
            { eventType: 'decision_made', decision: 'ALLOW' },
            { eventType: 'decision_made', decision: 'DENY' },
        ]);
        const snap = getKpiSnapshot();
        expect(snap.verification_success_rate).toBeCloseTo(2 / 3);
    });

    it('counts deny_credential_revoked_total', () => {
        setEvents([
            { eventType: 'decision_made', decision: 'DENY', decisionCode: 'DENY_CREDENTIAL_REVOKED' },
            { eventType: 'decision_made', decision: 'DENY', decisionCode: 'DENY_CREDENTIAL_REVOKED' },
        ]);
        const snap = getKpiSnapshot();
        expect(snap.deny_credential_revoked_total).toBe(2);
    });

    it('counts replay blocks', () => {
        setEvents([
            { eventType: 'decision_made', decision: 'DENY', decisionCode: 'DENY_BINDING_NONCE_REPLAY' },
        ]);
        const snap = getKpiSnapshot();
        expect(snap.replay_block_rate).toBe(1); // replayDenies/replayAttempts = 1/1
    });

    it('latency p50 computed from decision events', () => {
        setEvents([
            { eventType: 'decision_made', decision: 'ALLOW', latencyMs: 10 },
            { eventType: 'decision_made', decision: 'ALLOW', latencyMs: 20 },
            { eventType: 'decision_made', decision: 'ALLOW', latencyMs: 30 },
        ]);
        const snap = getKpiSnapshot();
        expect(snap.latency_p50_ms).toBe(20);
    });
});

describe('getKpiSnapshot — security_profile_score', () => {
    it('deducts 60 points when false_allow adjudications present', () => {
        setEvents([
            { eventType: 'adjudication_recorded', details: { outcome: 'false_allow' } },
        ]);
        const snap = getKpiSnapshot();
        // Base deductions without strong reauth (-10) and allowlist webauthn (-10) = 80, minus 60 = 20
        expect(snap.security_profile_score).toBeLessThan(50);
    });

    it('reaches max score 100 with strong reauth + signed webauthn + secret configured', () => {
        process.env.REQUIRE_STRONG_REAUTH = '1';
        process.env.WEBAUTHN_VERIFY_MODE = 'signed';
        process.env.WEBAUTHN_ASSERTION_HMAC_SECRET = 'secret-value';
        const snap = getKpiSnapshot();
        expect(snap.security_profile_score).toBe(100);
    });
});

describe('getKpiSnapshot — cost estimates', () => {
    it('uses default cost per verification', () => {
        const snap = getKpiSnapshot();
        expect(snap.estimated_cost_per_verification_eur).toBe(0.002);
    });

    it('reads custom cost from env', () => {
        process.env.ESTIMATED_COST_PER_VERIFICATION_EUR = '0.005';
        const snap = getKpiSnapshot();
        expect(snap.estimated_cost_per_verification_eur).toBe(0.005);
    });

    it('counts allowed algorithms', () => {
        process.env.ALLOWED_ALGS = 'EdDSA,ES256,ES384';
        const snap = getKpiSnapshot();
        expect(snap.crypto_allowed_algs_count).toBe(3);
    });
});
