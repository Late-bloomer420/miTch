/**
 * AI-06: DENY_NO_MATCHING_RULE vs DENY_POLICY_MISMATCH — independent disambiguation
 *
 * F-06 finding: both codes cover "verifier doesn't match policy" but are distinct:
 * - NO_MATCHING_RULE: no policy rule matched the verifier pattern (engine path)
 * - POLICY_MISMATCH:  rule matched but security-critical capability is disabled (capability-negotiation path)
 *
 * This test verifies that each code is triggered by its specific condition and
 * that the two codes are NOT interchangeable.
 */
import { describe, it, expect } from 'vitest';
import { resolveConflict } from '../conflict-resolver';
import { DenyReasonCode } from '../deny-reason-codes';
import { negotiateCapabilities, type CapabilityFlags } from '../capability-negotiation';

// ─── Fixtures ─────────────────────────────────────────────────────────────

const SECURE_CAPS: CapabilityFlags = {
  layer0: true,
  layer1: true,
  'revocation-online': true,
  'revocation-offline': false,
  'replay-protection': true,
  'step-up': true,
};

// ─── Tests ────────────────────────────────────────────────────────────────

describe('Deny code disambiguation: NO_MATCHING_RULE vs POLICY_MISMATCH', () => {
  it('NO_MATCHING_RULE is produced when no rule matches the verifier (conflict-resolver path)', () => {
    // Simulate engine returning NO_MATCHING_RULE when findMatchingRule returns null
    const verdicts = [
      { verdict: 'DENY' as const, reasonCodes: [DenyReasonCode.NO_MATCHING_RULE], ruleId: undefined },
    ];
    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(DenyReasonCode.NO_MATCHING_RULE);
    expect(result.reasonCodes).not.toContain(DenyReasonCode.POLICY_MISMATCH);
  });

  it('POLICY_MISMATCH is produced when capability security flag is disabled (capability-negotiation path)', () => {
    const result = negotiateCapabilities({
      wallet: { protocolVersion: '1.0.0', capabilities: SECURE_CAPS },
      verifier: {
        protocolVersion: '1.0.0',
        capabilities: { ...SECURE_CAPS, 'replay-protection': false },
      },
    });
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCode).toBe(DenyReasonCode.POLICY_MISMATCH);
    expect(result.reasonCode).not.toBe(DenyReasonCode.NO_MATCHING_RULE);
  });

  it('the two codes are distinct enum values', () => {
    expect(DenyReasonCode.NO_MATCHING_RULE).not.toBe(DenyReasonCode.POLICY_MISMATCH);
  });

  it('NO_MATCHING_RULE string value is DENY_NO_MATCHING_RULE', () => {
    expect(DenyReasonCode.NO_MATCHING_RULE).toBe('DENY_NO_MATCHING_RULE');
  });

  it('POLICY_MISMATCH string value is DENY_POLICY_MISMATCH', () => {
    expect(DenyReasonCode.POLICY_MISMATCH).toBe('DENY_POLICY_MISMATCH');
  });
});
