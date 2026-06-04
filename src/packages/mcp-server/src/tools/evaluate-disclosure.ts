/**
 * Tool: askmi_evaluate_disclosure
 *
 * Evaluates a verifier disclosure request against the AskMI privacy policy engine.
 * Returns a signed DecisionCapsule with verdict ALLOW | DENY | PROMPT, reason codes,
 * and (on ALLOW) the selective disclosure plan.
 *
 * Fail-closed: any ambiguity -> DENY. Never default to ALLOW.
 *
 * Status: STUB -- returns DENY / NOT_IMPLEMENTED until @askmi/policy-engine is wired.
 * See docs/mcp-server-architecture.md section 4-5 for the full spec.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod/v3';
import { randomUUID } from 'crypto';

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

interface DecisionCapsuleStub {
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  decision_id: string;
  policy_hash: string;
  reason_codes: string[];
  evaluated_at: number;
  stub: true;
  stub_message: string;
}

export function registerEvaluateDisclosure(server: McpServer): void {
  server.registerTool(
    'askmi_evaluate_disclosure',
    {
      description:
        'Evaluate a verifier disclosure request against the AskMI privacy policy engine. ' +
        'Returns a DecisionCapsule with verdict ALLOW | DENY | PROMPT and reason codes. ' +
        'Fail-closed: ambiguous or incomplete requests always resolve to DENY.',
      inputSchema: EvaluateDisclosureShape,
      annotations: {
        readOnlyHint: false,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    async (_args) => {
      // STUB -- wire @askmi/policy-engine here:
      //   const engine = new PolicyEngine(await loadDefaultPolicy());
      //   const result = await engine.evaluate(_args.verifier_request, _args.context);
      //   return formatResult(result, _args.response_format);

      const capsule: DecisionCapsuleStub = {
        verdict: 'DENY',
        decision_id: randomUUID(),
        policy_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        reason_codes: ['NOT_IMPLEMENTED'],
        evaluated_at: Date.now(),
        stub: true,
        stub_message:
          'askmi_evaluate_disclosure is a stub. ' +
          'Wire @askmi/policy-engine to activate. ' +
          'See docs/mcp-server-architecture.md section 10.',
      };

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(capsule, null, 2) }],
      };
    },
  );
}
