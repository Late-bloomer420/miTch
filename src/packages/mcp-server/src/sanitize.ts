/**
 * Output sanitisation for the MCP server — the "Controlled Insight" boundary.
 *
 * The PolicyEngine result is rich: it carries the selected credential id, the
 * issuer trust refs, request/policy hashes, a pairwise DID, a wallet
 * attestation signature, and the full original request. An LLM agent must see
 * NONE of that. It is only entitled to the *verdict* and structured reasoning:
 * would disclosure be allowed, and which claim NAMES are in scope.
 *
 * This module builds a whitelist object field-by-field. It never spreads the
 * engine result or the DecisionCapsule, so a future engine that adds a new
 * (possibly sensitive) field cannot silently leak it through this tool.
 *
 * StoredCredentialMetadata in AskMI holds claim *names*, not values, so there
 * are no raw attribute values to leak at this layer — but credential ids and
 * issuer DIDs are linkable identifiers and are deliberately dropped.
 */

import type { PolicyEvaluationResult } from '@askmi/shared-types';

const ZERO_POLICY_HASH = '0'.repeat(64);

/**
 * The only shape the agent ever receives. Verdict + structured reasoning,
 * claim names in scope, and an explicit `scope` tag. No PII, no identifiers.
 */
export interface ControlledInsight {
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  decision_id: string;
  policy_hash: string;
  reason_codes: string[];
  /** Raw claim NAMES that would be disclosed on ALLOW (never values). */
  disclosed_claims: string[];
  /** ZKP/predicate claim NAMES that would be proven without disclosure. */
  proven_claims: string[];
  /** Explicitly identifies whether the result came from mock or local scope. */
  scope: 'mock' | 'local';
  evaluated_at: string;
}

function randomDecisionId(): string {
  // Node 18+ / 20+ global crypto.
  return globalThis.crypto.randomUUID();
}

/**
 * Reduce a full PolicyEvaluationResult to the agent-safe ControlledInsight.
 * Pulls only whitelisted, non-identifying fields.
 */
export function sanitizeDecision(
  result: PolicyEvaluationResult,
  scope: ControlledInsight['scope'] = 'mock',
): ControlledInsight {
  const capsule = result.decisionCapsule;

  // Claim names come from the authorised requirements. On DENY there is no
  // capsule, so these are empty — nothing is in scope to disclose.
  const requirements = capsule?.authorized_requirements ?? [];
  const disclosed = new Set<string>();
  const proven = new Set<string>();
  for (const req of requirements) {
    for (const c of req.allowed_claims ?? []) disclosed.add(c);
    for (const c of req.proven_claims ?? []) proven.add(c);
  }

  const verdict = result.verdict as ControlledInsight['verdict'];

  return {
    verdict,
    decision_id: capsule?.decision_id ?? randomDecisionId(),
    policy_hash: capsule?.policy_hash ?? ZERO_POLICY_HASH,
    reason_codes: [...result.reasonCodes],
    disclosed_claims: [...disclosed],
    proven_claims: [...proven],
    scope,
    evaluated_at: new Date().toISOString(),
  };
}

/** Human-readable Markdown rendering of a ControlledInsight (response_format=markdown). */
export function formatInsightMarkdown(insight: ControlledInsight): string {
  const verdictIcon =
    insight.verdict === 'ALLOW' ? '✅' : insight.verdict === 'PROMPT' ? '🟡' : '⛔';
  const lines = [
    `### Disclosure verdict: ${verdictIcon} **${insight.verdict}**  _(scope: ${insight.scope})_`,
    '',
    `- **Decision ID:** \`${insight.decision_id}\``,
    `- **Policy hash:** \`${insight.policy_hash}\``,
    `- **Reason codes:** ${insight.reason_codes.length ? insight.reason_codes.map((r) => `\`${r}\``).join(', ') : '_none_'}`,
    `- **Would disclose (raw claim names):** ${insight.disclosed_claims.length ? insight.disclosed_claims.join(', ') : '_none_'}`,
    `- **Would prove (ZKP, no value shared):** ${insight.proven_claims.length ? insight.proven_claims.join(', ') : '_none_'}`,
    `- **Evaluated at:** ${insight.evaluated_at}`,
  ];
  return lines.join('\n');
}
