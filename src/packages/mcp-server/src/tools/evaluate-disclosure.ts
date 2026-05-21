/**
 * Tool: mitch_evaluate_disclosure
 *
 * Evaluates a verifier disclosure request against the miTch privacy policy engine.
 * Returns a signed DecisionCapsule with verdict ALLOW | DENY | PROMPT, reason codes,
 * and (on ALLOW) the selective disclosure plan.
 *
 * Fail-closed: any ambiguity → DENY. Never default to ALLOW.
 *
 * Status: STUB — returns DENY / NOT_IMPLEMENTED.
 *
 * Wiring is INTENTIONALLY frozen until a concrete consumer story exists. The
 * gating question is: who calls this tool and where does their Policy come
 * from? See docs/mcp-server-architecture.md §9.4 + §10.3. Embedding a default
 * policy would produce real DENY/PROMPT/ALLOW decisions against an
 * unauthorized rule set — that conflicts with the project's fail-closed,
 * autorisierte-Policy-only stance. Better to keep returning DENY/NOT_IMPLEMENTED
 * and treat any caller as "no policy configured".
 *
 * Wiring checklist (when the consumer is decided):
 *   1. Resolve the Policy (from file / from policy-engine.catalog / from caller)
 *   2. Map the agent-friendly input to a `DisclosureRequest` (see types.ts)
 *   3. Call `evaluateDisclosureRequest(req, policy)` from @mitch/policy-engine
 *   4. Wrap the result with `createDecisionCapsule({decision, policy, request, timestamp})`
 *   5. Replace the stub body and return the real DecisionCapsule
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { randomUUID } from 'crypto';

// ── Input schemas ────────────────────────────────────────────────────────────

const VerifierRequestSchema = z.object({
  verifier_id: z
    .string()
    .min(1)
    .max(512)
    .describe('DID or origin URL of the requesting verifier (e.g. did:web:rp.example)'),
  requested_claims: z
    .array(z.string().min(1).max(128))
    .min(1)
    .max(32)
    .describe('Claim names the verifier is requesting (e.g. ["dateOfBirth", "givenName"])'),
  purpose: z
    .string()
    .min(1)
    .max(512)
    .describe('Purpose statement required for GDPR Art. 6 lawful basis'),
  nonce: z
    .string()
    .min(8)
    .max(256)
    .describe('Anti-replay nonce — caller must generate per-request (min 8 chars)'),
});

const ContextSchema = z.object({
  user_did: z
    .string()
    .min(1)
    .max(512)
    .describe('DID of the credential holder'),
  interaction: z
    .object({
      channel: z
        .enum(['web', 'mobile', 'nfc', 'qr'])
        .optional()
        .describe('Interaction channel — influences risk scoring'),
      user_agent: z
        .string()
        .max(512)
        .optional()
        .describe('User-agent string (truncated to 512 chars)'),
    })
    .optional(),
  override_granted: z
    .boolean()
    .optional()
    .describe(
      'Set to true if the user explicitly consented after a PROMPT verdict. ' +
        'Ignored for DENY verdicts with hard-block reason codes.',
    ),
});

// ── Output type (stub) ───────────────────────────────────────────────────────

interface DecisionCapsuleStub {
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  decision_id: string;
  policy_hash: string;
  reason_codes: string[];
  evaluated_at: number;
  stub: true;
  stub_message: string;
}

// ── Registration ─────────────────────────────────────────────────────────────

export function registerEvaluateDisclosure(server: McpServer): void {
  server.tool(
    'mitch_evaluate_disclosure',
    'Evaluate a verifier disclosure request against the miTch privacy policy engine. ' +
      'Returns a signed DecisionCapsule with verdict ALLOW | DENY | PROMPT and reason codes. ' +
      'On ALLOW the response also contains the selective disclosure plan (which claims to release). ' +
      'Fail-closed: ambiguous or incomplete requests always resolve to DENY.',
    {
      verifier_request: VerifierRequestSchema,
      context: ContextSchema,
      policy_hash: z
        .string()
        .regex(/^[0-9a-f]{64}$/)
        .optional()
        .describe('Pin evaluation to a specific policy version (hex SHA-256, 64 chars)'),
      response_format: z
        .enum(['json', 'markdown'])
        .default('json')
        .describe('Preferred output format — json (default) or markdown for human-readable output'),
    },
    async (_args) => {
      // ── STUB ────────────────────────────────────────────────────────────────
      // Replace this block with real policy-engine invocation:
      //
      //   const engine = new PolicyEngine(await loadDefaultPolicy());
      //   const result = await engine.evaluate(
      //     args.verifier_request,
      //     args.context,
      //     args.policy_hash,
      //   );
      //   return formatResult(result, args.response_format);
      //
      const capsule: DecisionCapsuleStub = {
        verdict: 'DENY',
        decision_id: randomUUID(),
        // Placeholder hash — replace with real SHA-256(policy manifest) on wiring
        policy_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        reason_codes: ['NOT_IMPLEMENTED'],
        evaluated_at: Date.now(),
        stub: true,
        stub_message:
          'mitch_evaluate_disclosure is a stub. ' +
          'Wire @mitch/policy-engine to activate real evaluation. ' +
          'See docs/mcp-server-architecture.md §10 for next steps.',
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(capsule, null, 2),
          },
        ],
      };
    },
  );
}
