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
import {
  DenyReasonCode,
  DENY_REASON_CATALOG,
  getDenyMessage,
  getVerifierDenyMessage,
} from '../deny-reason-codes';

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
  it('getDenyMessage executes in < 1ms for all codes (baseline)', () => {
    for (const code of Object.values(DenyReasonCode)) {
      const start = performance.now();
      getDenyMessage(code, 'verifier');
      getDenyMessage(code, 'user');
      getDenyMessage(code, 'audit');
      const elapsed = performance.now() - start;

      // Message lookup should be trivially fast (< 1ms)
      expect(elapsed).toBeLessThan(1);
    }
  });

  it('DOCUMENTED: response-level timing padding is required for Phase 6', () => {
    // This test exists to document the requirement.
    // The actual implementation of constant-time response padding
    // is deferred to Phase 6 (see spec 108 §3.4).
    //
    // When implementing, the PolicyEngine.evaluate() method should:
    // 1. Record start time
    // 2. Compute result
    // 3. Pad to FLOOR_MS (e.g., 50ms) before returning
    //
    // This prevents verifiers from distinguishing fast DENY (cache hit)
    // from slow DENY (full evaluation) via timing analysis.
    expect(true).toBe(true);
  });
});
