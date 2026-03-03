/**
 * @module @mitch/policy-engine/conflict-resolver
 *
 * Deterministic Policy Conflict Resolution (Spec 108)
 *
 * When multiple policy rules match a request, this module resolves
 * the conflict using deny-wins precedence:
 *
 * 1. ANY DENY → DENY
 * 2. ANY PROMPT (no DENY) → PROMPT
 * 3. ALL ALLOW → ALLOW
 *
 * Guarantees:
 * - Same inputs → same output (no randomness)
 * - Unknown policy version → DENY (fail-closed)
 * - Missing policy → DENY
 * - Higher layer cannot override lower layer's deny
 */

import { DenyReasonCode } from './deny-reason-codes';

/**
 * Known policy schema versions.
 * Evaluation against unknown versions is rejected fail-closed.
 */
export const KNOWN_POLICY_VERSIONS = new Set(['1.0.0', '1.1.0']);

export type Verdict = 'ALLOW' | 'DENY' | 'PROMPT';

export interface VerdictWithReason {
  verdict: Verdict;
  reasonCodes: string[];
  ruleId?: string;
}

/**
 * Resolve conflicting verdicts from multiple matching rules.
 * Deny-wins: most restrictive interpretation always prevails.
 *
 * This function is pure and deterministic — no side effects, no randomness.
 */
export function resolveConflict(verdicts: VerdictWithReason[]): VerdictWithReason {
  // Fail-closed: no verdicts → DENY
  if (verdicts.length === 0) {
    return {
      verdict: 'DENY',
      reasonCodes: [DenyReasonCode.NO_MATCHING_RULE],
    };
  }

  // Single verdict — no conflict
  if (verdicts.length === 1) {
    return verdicts[0];
  }

  // Deny-wins: if ANY verdict is DENY, final is DENY
  const denyVerdicts = verdicts.filter(v => v.verdict === 'DENY');
  if (denyVerdicts.length > 0) {
    // Merge all deny reason codes
    const allReasons = denyVerdicts.flatMap(v => v.reasonCodes);
    // Add conflict marker
    allReasons.push(DenyReasonCode.CONFLICT_DENY_WINS);
    return {
      verdict: 'DENY',
      reasonCodes: [...new Set(allReasons)], // deduplicate
      ruleId: denyVerdicts[0].ruleId,
    };
  }

  // If any PROMPT (no DENY) → PROMPT
  const promptVerdicts = verdicts.filter(v => v.verdict === 'PROMPT');
  if (promptVerdicts.length > 0) {
    const allReasons = verdicts.flatMap(v => v.reasonCodes);
    return {
      verdict: 'PROMPT',
      reasonCodes: [...new Set(allReasons)],
      ruleId: promptVerdicts[0].ruleId,
    };
  }

  // All ALLOW
  const allReasons = verdicts.flatMap(v => v.reasonCodes);
  return {
    verdict: 'ALLOW',
    reasonCodes: [...new Set(allReasons)],
    ruleId: verdicts[0].ruleId,
  };
}

/**
 * Check if a policy version is known/supported.
 * Unknown versions must be rejected fail-closed.
 */
export function isPolicyVersionKnown(version: string): boolean {
  return KNOWN_POLICY_VERSIONS.has(version);
}

/**
 * Validate that a policy is present and has a known version.
 * Returns a DENY verdict if validation fails, null if OK.
 */
export function validatePolicyOrDeny(policy: unknown): VerdictWithReason | null {
  if (!policy || typeof policy !== 'object') {
    return {
      verdict: 'DENY',
      reasonCodes: [DenyReasonCode.POLICY_MISSING],
    };
  }

  const manifest = policy as { version?: string };

  if (!manifest.version) {
    return {
      verdict: 'DENY',
      reasonCodes: [DenyReasonCode.POLICY_MISSING],
    };
  }

  if (!isPolicyVersionKnown(manifest.version)) {
    return {
      verdict: 'DENY',
      reasonCodes: [DenyReasonCode.POLICY_UNSUPPORTED_VERSION],
    };
  }

  return null; // OK
}
