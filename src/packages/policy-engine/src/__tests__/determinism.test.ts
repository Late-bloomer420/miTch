/**
 * Deterministic Conflict Resolution Tests (Spec 108)
 *
 * Verifies:
 * - Two conflicting policies → deterministic output (deny-wins)
 * - Same inputs → always same output (no randomness)
 * - Unknown policy version → DENY (fail-closed)
 * - Missing policy → DENY
 * - Layer inheritance: higher layer can't override lower layer's deny
 */

import { describe, it, expect } from 'vitest';
import {
  resolveConflict,
  validatePolicyOrDeny,
  isPolicyVersionKnown,
  KNOWN_POLICY_VERSIONS,
  type VerdictWithReason,
} from '../conflict-resolver';
import { DenyReasonCode } from '../deny-reason-codes';

describe('Conflict Resolution: deny-wins', () => {
  it('DENY wins over ALLOW when two rules conflict', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'rule-a' },
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.LAYER_VIOLATION], ruleId: 'rule-b' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(DenyReasonCode.LAYER_VIOLATION);
    expect(result.reasonCodes).toContain(DenyReasonCode.CONFLICT_DENY_WINS);
  });

  it('DENY wins over PROMPT', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'PROMPT', reasonCodes: ['CONSENT_REQUIRED'], ruleId: 'rule-a' },
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.CLAIM_NOT_ALLOWED], ruleId: 'rule-b' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('DENY');
  });

  it('PROMPT wins over ALLOW (no DENY present)', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'rule-a' },
      { verdict: 'PROMPT', reasonCodes: ['CONSENT_REQUIRED'], ruleId: 'rule-b' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('PROMPT');
  });

  it('all ALLOW → ALLOW', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'rule-a' },
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'rule-b' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('ALLOW');
  });

  it('empty verdicts → DENY (fail-closed)', () => {
    const result = resolveConflict([]);
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(DenyReasonCode.NO_MATCHING_RULE);
  });

  it('single verdict passes through unchanged', () => {
    const single: VerdictWithReason = {
      verdict: 'ALLOW',
      reasonCodes: ['RULE_MATCHED'],
      ruleId: 'rule-x',
    };

    const result = resolveConflict([single]);
    expect(result).toEqual(single);
  });

  it('multiple DENYs merge reason codes and deduplicate', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.LAYER_VIOLATION], ruleId: 'rule-a' },
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.LAYER_VIOLATION, DenyReasonCode.EXPIRED], ruleId: 'rule-b' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('DENY');
    // Deduplicated
    const layerCount = result.reasonCodes.filter(r => r === DenyReasonCode.LAYER_VIOLATION).length;
    expect(layerCount).toBe(1);
    expect(result.reasonCodes).toContain(DenyReasonCode.EXPIRED);
    expect(result.reasonCodes).toContain(DenyReasonCode.CONFLICT_DENY_WINS);
  });
});

describe('Determinism: same inputs → same output', () => {
  it('produces identical output for 100 consecutive runs', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'rule-a' },
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.UNKNOWN_VERIFIER], ruleId: 'rule-b' },
      { verdict: 'PROMPT', reasonCodes: ['CONSENT_REQUIRED'], ruleId: 'rule-c' },
    ];

    const firstResult = resolveConflict(verdicts);

    for (let i = 0; i < 100; i++) {
      const result = resolveConflict(verdicts);
      expect(result.verdict).toBe(firstResult.verdict);
      expect(result.reasonCodes).toEqual(firstResult.reasonCodes);
    }
  });

  it('order of verdicts does not change outcome', () => {
    const a: VerdictWithReason = { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'rule-a' };
    const b: VerdictWithReason = { verdict: 'DENY', reasonCodes: [DenyReasonCode.EXPIRED], ruleId: 'rule-b' };
    const c: VerdictWithReason = { verdict: 'PROMPT', reasonCodes: ['CONSENT_REQUIRED'], ruleId: 'rule-c' };

    const r1 = resolveConflict([a, b, c]);
    const r2 = resolveConflict([c, a, b]);
    const r3 = resolveConflict([b, c, a]);

    expect(r1.verdict).toBe('DENY');
    expect(r2.verdict).toBe('DENY');
    expect(r3.verdict).toBe('DENY');
  });
});

describe('Unknown policy version → DENY (fail-closed)', () => {
  it('rejects unknown version', () => {
    const result = validatePolicyOrDeny({ version: '99.99.99', rules: [], trustedIssuers: [] });
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('DENY');
    expect(result!.reasonCodes).toContain(DenyReasonCode.POLICY_UNSUPPORTED_VERSION);
  });

  it('accepts known version', () => {
    for (const v of KNOWN_POLICY_VERSIONS) {
      const result = validatePolicyOrDeny({ version: v, rules: [], trustedIssuers: [] });
      expect(result).toBeNull(); // null = OK
    }
  });

  it('isPolicyVersionKnown returns false for unknown', () => {
    expect(isPolicyVersionKnown('0.0.1')).toBe(false);
    expect(isPolicyVersionKnown('2.0.0')).toBe(false);
    expect(isPolicyVersionKnown('')).toBe(false);
  });
});

describe('Missing policy → DENY (fail-closed)', () => {
  it('null policy → DENY', () => {
    const result = validatePolicyOrDeny(null);
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('DENY');
    expect(result!.reasonCodes).toContain(DenyReasonCode.POLICY_MISSING);
  });

  it('undefined policy → DENY', () => {
    const result = validatePolicyOrDeny(undefined);
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('DENY');
  });

  it('empty object (no version) → DENY', () => {
    const result = validatePolicyOrDeny({});
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('DENY');
    expect(result!.reasonCodes).toContain(DenyReasonCode.POLICY_MISSING);
  });
});

describe('Layer inheritance: higher layer cannot override lower deny', () => {
  it('Layer 2 ALLOW cannot override Layer 0 DENY', () => {
    const verdicts: VerdictWithReason[] = [
      // Layer 0 universal rule denies
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.LAYER_VIOLATION], ruleId: 'layer-0-rule' },
      // Layer 2 specific rule allows
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'layer-2-rule' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(DenyReasonCode.LAYER_VIOLATION);
  });

  it('Layer 1 DENY persists even with Layer 2 ALLOW and Layer 0 ALLOW', () => {
    const verdicts: VerdictWithReason[] = [
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'layer-0-rule' },
      { verdict: 'DENY', reasonCodes: [DenyReasonCode.CLAIM_NOT_ALLOWED], ruleId: 'layer-1-rule' },
      { verdict: 'ALLOW', reasonCodes: ['RULE_MATCHED'], ruleId: 'layer-2-rule' },
    ];

    const result = resolveConflict(verdicts);
    expect(result.verdict).toBe('DENY');
  });
});
