/**
 * Tool: askmi_evaluate_disclosure
 *
 * Evaluates a verifier disclosure request against the AskMI privacy policy
 * engine and returns a sanitised "Controlled Insight" verdict
 * (ALLOW | DENY | PROMPT) with reason codes and the claim NAMES in scope.
 *
 * Fail-closed: any ambiguity, validation gap or internal error resolves to DENY.
 * Never default to ALLOW.
 *
 * Status: WIRED to @askmi/policy-engine. By default it runs over the
 * NON-AUTHORITATIVE mock scope (see server-scope.ts). If MITCH_WALLET_DB is
 * set, it loads an explicit local JSON evaluation scope via evaluation-scope.ts.
 * The agent only ever sees the sanitised verdict (see sanitize.ts), never
 * credentials, identifiers or signatures.
 *
 * See docs/mcp-server-architecture.md §4–6 and §11 (thaw decision).
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod/v3';
import { PolicyEngine } from '@askmi/policy-engine';
import type {
  VerifierRequest,
  PolicyEvaluationResult,
} from '@askmi/shared-types';
import type { EvaluationContext } from '@askmi/policy-engine';
import {
  sanitizeDecision,
  formatInsightMarkdown,
  type ControlledInsight,
} from '../sanitize.js';
import { loadEvaluationScope } from '../evaluation-scope.js';

const VerifierRequestSchema = z.object({
  verifier_id: z.string().min(1).max(512).describe('DID or origin URL of the requesting verifier'),
  requested_claims: z
    .array(z.string().min(1).max(128))
    .min(1)
    .max(32)
    .describe('Claim names the verifier is requesting'),
  purpose: z.string().min(1).max(512).describe('Purpose statement for GDPR Art. 6 lawful basis'),
  nonce: z.string().min(8).max(256).describe('Anti-replay nonce, min 8 chars, per-request'),
});

const ContextSchema = z.object({
  user_did: z.string().min(1).max(512).describe('DID of the credential holder'),
  interaction: z
    .object({
      channel: z.enum(['web', 'mobile', 'nfc', 'qr']).optional(),
      user_agent: z.string().max(512).optional(),
    })
    .optional(),
  override_granted: z
    .boolean()
    .optional()
    .describe('True if user explicitly consented after a PROMPT verdict'),
});

const EvaluateDisclosureShape = {
  verifier_request: VerifierRequestSchema,
  context: ContextSchema,
  policy_hash: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional()
    .describe('Pin to specific policy version (hex SHA-256, 64 chars)'),
  response_format: z
    .enum(['json', 'markdown'])
    .default('json')
    .describe('Output format: json (default) or markdown'),
};

type EvaluateDisclosureArgs = {
  verifier_request: z.infer<typeof VerifierRequestSchema>;
  context: z.infer<typeof ContextSchema>;
  policy_hash?: string;
  response_format?: 'json' | 'markdown';
};

/** Map the MCP wire input onto the engine's VerifierRequest (legacy claims path). */
function toEngineRequest(args: EvaluateDisclosureArgs): VerifierRequest {
  return {
    verifierId: args.verifier_request.verifier_id,
    nonce: args.verifier_request.nonce,
    purpose: args.verifier_request.purpose,
    requestedClaims: args.verifier_request.requested_claims,
  };
}

/** Map the MCP context onto the engine's EvaluationContext.
 *  Interaction risk-metadata is intentionally NOT forwarded — the mock scope
 *  evaluates policy intent, not device risk. */
function toEngineContext(args: EvaluateDisclosureArgs): EvaluationContext {
  return {
    timestamp: Date.now(),
    userDID: args.context.user_did,
    overrideGranted: args.context.override_granted,
  };
}

/** Fail-closed DENY insight used when evaluation cannot complete safely. */
function denyInsight(reasonCode: string, scope: ControlledInsight['scope']): ControlledInsight {
  return {
    verdict: 'DENY',
    decision_id: globalThis.crypto.randomUUID(),
    policy_hash: '0'.repeat(64),
    reason_codes: [reasonCode],
    disclosed_claims: [],
    proven_claims: [],
    scope,
    evaluated_at: new Date().toISOString(),
  };
}

export function registerEvaluateDisclosure(server: McpServer): void {
  server.registerTool(
    'askmi_evaluate_disclosure',
    {
      description:
        'Evaluate a verifier disclosure request against the AskMI privacy policy engine. ' +
        'Returns a Controlled Insight verdict ALLOW | DENY | PROMPT with reason codes and ' +
        'the claim names in scope — never credential values, ids or issuer identities. ' +
        'Fail-closed: ambiguous or incomplete requests always resolve to DENY. ' +
        'Runs on a non-authoritative mock scope (responses tagged scope:"mock").',
      inputSchema: EvaluateDisclosureShape,
      annotations: {
        readOnlyHint: false,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    async (args) => {
      let insight: ControlledInsight;
      let insightScope: ControlledInsight['scope'] = process.env.MITCH_WALLET_DB?.trim()
        ? 'local'
        : 'mock';

      try {
        const scope = await loadEvaluationScope();
        insightScope = scope.kind;
        const engine = new PolicyEngine();
        const result: PolicyEvaluationResult = await engine.evaluate(
          toEngineRequest(args as EvaluateDisclosureArgs),
          {
            ...toEngineContext(args as EvaluateDisclosureArgs),
            userDID: scope.userDid,
          },
          scope.credentials,
          scope.policy,
        );
        insight = sanitizeDecision(result, scope.kind);
      } catch (err) {
        // stderr only — stdout is reserved for the MCP wire protocol.
        // Never surface stack traces to the agent (architecture §6).
        const message = err instanceof Error ? err.message : String(err);
        process.stderr.write(`[AskMI-mcp] evaluate_disclosure failed: ${message}\n`);
        insight = denyInsight('ERR_EVALUATION_FAILED', insightScope);
      }

      const format = (args as EvaluateDisclosureArgs).response_format ?? 'json';
      const text =
        format === 'markdown'
          ? formatInsightMarkdown(insight)
          : JSON.stringify(insight, null, 2);

      return {
        content: [{ type: 'text' as const, text }],
        structuredContent: insight as unknown as Record<string, unknown>,
      };
    },
  );
}
