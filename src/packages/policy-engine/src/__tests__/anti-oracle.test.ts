/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Anti-Oracle Tests (Spec 108)
 *
 * Verifies:
 * - Different deny reasons produce same verifier-facing message
 * - Verifier cannot distinguish "no such user" from "policy denied"
 * - Timing oracle requirement documented and measurable
 */

import { describe, it, expect } from 'vitest';
import { PolicyEngine, type EvaluationContext } from '../engine';
import { ProtectionLayer } from '@askmi/layer-resolver';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@askmi/shared-types';
import {
  DenyReasonCode,
  DENY_REASON_CATALOG,
  getDenyMessage,
  getVerifierDenyMessage,
} from '../deny-reason-codes';

const _cred = (o: Partial<StoredCredentialMetadata> = {}): StoredCredentialMetadata => ({
  id: 'cred-001', type: ['IDCredential'], issuer: 'did:example:gov',
  issuedAt: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 365 * 864e5).toISOString(),
  claims: ['age'], ...o,
});
const _policy = (o: Partial<PolicyManifest> = {}): PolicyManifest => ({
  version: '1.0.0',
  trustedIssuers: [{ did: 'did:example:gov', name: 'Gov', credentialTypes: ['IDCredential'] }],
  rules: [{
    id: 'r', verifierPattern: 'did:web:known.example',
    minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, allowedClaims: ['age'], provenClaims: [],
    requiresTrustedIssuer: true, maxCredentialAgeDays: 365, requiresUserConsent: false, priority: 10,
  }],
  globalSettings: { blockUnknownVerifiers: true }, ...o,
});
const _ctx = (): EvaluationContext => ({ timestamp: Date.now(), userDID: 'did:example:alice' });

describe('Anti-Oracle: verifier message bucketing', () => {
  /**
   * These deny codes MUST all produce the same verifier-facing message.
   * This is the core anti-oracle property: a verifier cannot distinguish
   * between these different denial reasons.
   */
  const INDISTINGUISHABLE_CODES = [
    DenyReasonCode.EXPIRED,
    DenyReasonCode.REVOKED,
    DenyReasonCode.CREDENTIAL_TOO_OLD,
    DenyReasonCode.NO_SUITABLE_CREDENTIAL,
    DenyReasonCode.POLICY_MISMATCH,
    DenyReasonCode.POLICY_MISSING,
    DenyReasonCode.POLICY_UNSUPPORTED_VERSION,
    DenyReasonCode.NO_MATCHING_RULE,
    DenyReasonCode.CLAIM_NOT_ALLOWED,
    DenyReasonCode.LAYER_VIOLATION,
    DenyReasonCode.UNKNOWN_VERIFIER,
    DenyReasonCode.UNTRUSTED_ISSUER,
    DenyReasonCode.BINDING_FAILED,
    DenyReasonCode.NONCE_REPLAY,
    DenyReasonCode.HASH_MISMATCH,
    DenyReasonCode.AUDIENCE_MISMATCH,
    DenyReasonCode.BINDING_EXPIRED,
    DenyReasonCode.CRYPTO_VERIFY_FAILED,
    DenyReasonCode.UNSUPPORTED_ALGORITHM,
    DenyReasonCode.KEY_STATUS_INVALID,
    DenyReasonCode.AGENT_NOT_AUTHORIZED,
    DenyReasonCode.AGENT_LIMIT_EXCEEDED,
    DenyReasonCode.FUTURE_ISSUANCE,
    DenyReasonCode.MINIMIZATION_VIOLATION,
    DenyReasonCode.JURISDICTION_INCOMPATIBLE,
    DenyReasonCode.CONFLICT_DENY_WINS,
    DenyReasonCode.INTERNAL_SAFE_FAILURE,
  ];

  it('all policy-distinguishing deny codes produce identical verifier message', () => {
    const messages = INDISTINGUISHABLE_CODES.map(code => getVerifierDenyMessage(code));
    const unique = new Set(messages);

    expect(unique.size).toBe(1);
    expect(messages[0]).toBe('Verification could not be completed.');
  });

  it('verifier CANNOT distinguish "no such user" from "policy denied"', () => {
    // These are the specific pair from the spec requirement
    const noUser = getVerifierDenyMessage(DenyReasonCode.NO_MATCHING_RULE);
    const policyDenied = getVerifierDenyMessage(DenyReasonCode.POLICY_MISMATCH);
    const expired = getVerifierDenyMessage(DenyReasonCode.EXPIRED);
    const revoked = getVerifierDenyMessage(DenyReasonCode.REVOKED);

    expect(noUser).toBe(policyDenied);
    expect(noUser).toBe(expired);
    expect(noUser).toBe(revoked);
  });

  it('rate limit has its own bucket (verifier needs to know to back off)', () => {
    const msg = getVerifierDenyMessage(DenyReasonCode.RATE_LIMIT_EXCEEDED);
    expect(msg).toBe('Request rate exceeded.');
    // Must be different from generic bucket
    expect(msg).not.toBe('Verification could not be completed.');
  });

  it('user-action codes have their own bucket', () => {
    const consent = getVerifierDenyMessage(DenyReasonCode.CONSENT_REQUIRED);
    const presence = getVerifierDenyMessage(DenyReasonCode.PRESENCE_REQUIRED);

    expect(consent).toBe('User action required.');
    expect(presence).toBe('User action required.');
    expect(consent).not.toBe('Verification could not be completed.');
  });

  it('infrastructure codes have their own bucket', () => {
    const status = getVerifierDenyMessage(DenyReasonCode.STATUS_SOURCE_UNAVAILABLE);
    const quorum = getVerifierDenyMessage(DenyReasonCode.RESOLVER_QUORUM_FAILED);

    expect(status).toBe('Service temporarily unavailable.');
    expect(quorum).toBe('Service temporarily unavailable.');
  });
});

describe('Anti-Oracle: user messages ARE distinct (user owns the data)', () => {
  it('user sees different messages for different deny reasons', () => {
    const expired = getDenyMessage(DenyReasonCode.EXPIRED, 'user');
    const revoked = getDenyMessage(DenyReasonCode.REVOKED, 'user');
    const noCredential = getDenyMessage(DenyReasonCode.NO_SUITABLE_CREDENTIAL, 'user');

    // User messages should be helpful and distinct
    expect(expired).not.toBe(revoked);
    expect(expired).not.toBe(noCredential);
    expect(revoked).not.toBe(noCredential);
  });
});

describe('Anti-Oracle: audit messages have full detail', () => {
  it('every deny code has a non-empty audit message', () => {
    for (const code of Object.values(DenyReasonCode)) {
      const audit = getDenyMessage(code, 'audit');
      expect(audit).toBeTruthy();
      expect(audit.length).toBeGreaterThan(10);
    }
  });

  it('audit messages contain technical detail not in verifier messages', () => {
    // Audit should have specifics; verifier should be generic
    const auditExpired = getDenyMessage(DenyReasonCode.EXPIRED, 'audit');
    const verifierExpired = getDenyMessage(DenyReasonCode.EXPIRED, 'verifier');

    expect(auditExpired.length).toBeGreaterThan(verifierExpired.length);
    expect(auditExpired).toContain('expired');
  });
});

describe('Anti-Oracle: unknown codes fail-closed', () => {
  it('unknown deny code returns generic message (not an error)', () => {
    const msg = getDenyMessage('TOTALLY_UNKNOWN_CODE' as any, 'verifier');
    expect(msg).toBe('Verification could not be completed.');
  });

  it('unknown deny code returns safe user message', () => {
    const msg = getDenyMessage('TOTALLY_UNKNOWN_CODE' as any, 'user');
    expect(msg).toBeTruthy();
    // Should be the INTERNAL_SAFE_FAILURE user message
    expect(msg).toBe(getDenyMessage(DenyReasonCode.INTERNAL_SAFE_FAILURE, 'user'));
  });
});

describe('Anti-Oracle: catalog completeness', () => {
  it('every DenyReasonCode enum value has a catalog entry', () => {
    for (const code of Object.values(DenyReasonCode)) {
      const entry = DENY_REASON_CATALOG[code as DenyReasonCode];
      expect(entry, `Missing catalog entry for ${code}`).toBeDefined();
      expect(entry.user).toBeTruthy();
      expect(entry.verifier).toBeTruthy();
      expect(entry.audit).toBeTruthy();
    }
  });

  it('total verifier bucket count is ≤ 4 (anti-oracle surface area)', () => {
    const allVerifierMessages = Object.values(DENY_REASON_CATALOG).map(e => e.verifier);
    const uniqueMessages = new Set(allVerifierMessages);

    // We allow at most 4 distinct verifier messages
    // (generic, rate-limit, user-action, infra)
    expect(uniqueMessages.size).toBeLessThanOrEqual(4);
  });
});

describe('Anti-Oracle: timing oracle (documentation + baseline)', () => {
  /**
   * TIMING ORACLE REQUIREMENT (Spec 108 §3.4):
   *
   * All DENY paths should execute in approximately constant time.
   * For Phase 5 pilot, this is documented and measured but not enforced.
   *
   * Implementation options for Phase 6+:
   * 1. Constant-time padding: add delay so all paths take max(time, FLOOR_MS)
   * 2. Async batching: queue responses and flush on fixed intervals
   *
   * This test measures getDenyMessage timing to establish a baseline.
   * It does NOT enforce constant time (that requires response-level padding).
   */
  it('getDenyMessage is trivially fast on average (load-robust baseline)', () => {
    const codes = Object.values(DenyReasonCode);
    const ITERATIONS = 2000;

    const start = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      for (const code of codes) {
        getDenyMessage(code, 'verifier');
        getDenyMessage(code, 'user');
        getDenyMessage(code, 'audit');
      }
    }
    const elapsed = performance.now() - start;
    const perCall = elapsed / (ITERATIONS * codes.length * 3);

    // It is a pure catalog lookup — sub-microsecond per call. We assert the
    // AVERAGE over many iterations, not a single call: a single measurement is
    // dominated by GC/scheduling jitter on a loaded CI runner (the old
    // "< 1ms single call" assertion flaked at ~13ms). 0.1ms/call is a generous
    // ceiling that still catches a genuine pathological-slowness regression.
    expect(perCall).toBeLessThan(0.1);
  });
});

describe('Anti-Oracle: end-to-end DENY timing variance (GAP-3)', () => {
  it('indistinguishable DENY paths have bounded mean-timing spread', async () => {
    const engine = new PolicyEngine();
    const policy = _policy();
    const ITERS = 500;
    const WARMUP = 20;

    // Path A: unknown verifier (early return, engine.ts:202)
    const unknownVerifier = { verifierId: 'did:web:stranger.example', requestedClaims: ['age'],
      requirements: [{ credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: [] }],
      nonce: 'n' } as VerifierRequest;

    // Path B: known verifier, claim not allowed (mid-to-late return, engine.ts:273)
    const claimDenied = { verifierId: 'did:web:known.example', requestedClaims: ['ssn'],
      requirements: [{ credentialType: 'IDCredential', requestedClaims: ['ssn'], requestedProvenClaims: [] }],
      nonce: 'n' } as VerifierRequest;

    // Path C: known verifier, no suitable credential (holder-secret path)
    const noCredential = { verifierId: 'did:web:known.example', requestedClaims: ['age'],
      requirements: [{ credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: [] }],
      nonce: 'n' } as VerifierRequest;

    const credA = [_cred()];
    const credB = [_cred()];
    const credC: StoredCredentialMetadata[] = [];

    // Warm-up: discard results so JIT-compilation cost doesn't bias the first
    // path measured in the timed loop below.
    for (let i = 0; i < WARMUP; i++) {
      await engine.evaluate(unknownVerifier, _ctx(), credA, policy);
      await engine.evaluate(claimDenied, _ctx(), credB, policy);
      await engine.evaluate(noCredential, _ctx(), credC, policy);
    }

    // Interleaved sampling: each iteration measures A, then B, then C so that
    // GC/scheduler pauses are shared across all three paths rather than
    // systematically biasing one batch.
    let totalA = 0, totalB = 0, totalC = 0;
    for (let i = 0; i < ITERS; i++) {
      let t = performance.now();
      await engine.evaluate(unknownVerifier, _ctx(), credA, policy);
      totalA += performance.now() - t;

      t = performance.now();
      await engine.evaluate(claimDenied, _ctx(), credB, policy);
      totalB += performance.now() - t;

      t = performance.now();
      await engine.evaluate(noCredential, _ctx(), credC, policy);
      totalC += performance.now() - t;
    }

    const a = totalA / ITERS;
    const b = totalB / ITERS;
    const c = totalC / ITERS;

    const max = Math.max(a, b, c);
    const min = Math.min(a, b, c);
    // Amortized means, not single calls (single-call is GC/scheduler-dominated on CI).
    // Assert the SPREAD is bounded: no path leaks a holder secret via a large,
    // consistent latency gap. 2ms absolute spread tolerates JIT/GC noise while
    // still catching a pathological secret-dependent branch (e.g. an added I/O call).
    expect(max - min).toBeLessThan(2);
  });
});
