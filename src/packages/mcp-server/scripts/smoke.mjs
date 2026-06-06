/**
 * Smoke-test: drive the BUILT MCP server as a real stdio subprocess.
 *
 * Unlike the vitest suite (which uses an in-memory transport), this launches
 * `node dist/index.js` as an actual child process and talks to it over stdio.
 * It therefore also validates:
 *   - the dist build is runnable and registers its tools,
 *   - the stdio wire is not corrupted by stray stdout writes (architecture section 6:
 *     all server logging must go to stderr),
 *   - the three deterministic mock-scope verdicts (ALLOW / PROMPT / DENY),
 *   - the Controlled-Insight boundary (no credential ids / issuer DIDs leak).
 *
 * Run:  pnpm --filter @askmi/mcp-server smoke   (after `build`)
 * Exit: 0 on success, 1 on any failed assertion.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';

const SERVER_ENTRY = fileURLToPath(new URL('../dist/index.js', import.meta.url));

// Known mock-scope verifiers (public behaviour, kept decoupled from internals).
const LIQUOR_STORE = 'did:web:liquor-store.example.com';
const HOSPITAL = 'did:web:hospital.example.com';
const UNKNOWN = 'did:web:unknown-shady.example.com';

// Synthetic identifiers that must NEVER appear in a tool response.
const FORBIDDEN_SUBSTRINGS = ['mock-vc-age-0001', 'did:example:mock-gov-issuer'];

let failures = 0;
function check(label, cond, detail = '') {
  const ok = Boolean(cond);
  console.log(`${ok ? '  [OK]' : '  [FAIL]'} ${label}${detail ? ` - ${detail}` : ''}`);
  if (!ok) failures++;
}

function buildInput(verifierId, claims = ['age_over_18']) {
  return {
    verifier_request: {
      verifier_id: verifierId,
      requested_claims: claims,
      purpose: 'Smoke-test disclosure evaluation',
      nonce: 'smoke-nonce-12345678',
    },
    context: { user_did: 'did:example:smoke-holder' },
  };
}

async function callVerdict(client, verifierId) {
  const res = await client.callTool({
    name: 'askmi_evaluate_disclosure',
    arguments: buildInput(verifierId),
  });
  const raw = res.content[0].text;
  return { raw, insight: JSON.parse(raw) };
}

async function main() {
  const transport = new StdioClientTransport({
    command: process.execPath, // current node
    args: [SERVER_ENTRY],
  });
  const client = new Client({ name: 'mcp-smoke', version: '1.0.0' });

  console.log(`\nLaunching MCP server: ${SERVER_ENTRY}\n`);
  await client.connect(transport);

  console.log('Tool inventory:');
  const { tools } = await client.listTools();
  check('askmi_evaluate_disclosure is registered', tools.some((t) => t.name === 'askmi_evaluate_disclosure'));

  console.log('\nVerdict matrix (mock scope):');
  const allow = await callVerdict(client, LIQUOR_STORE);
  check('liquor-store -> ALLOW', allow.insight.verdict === 'ALLOW', allow.insight.verdict);
  check('ALLOW is tagged scope:"mock"', allow.insight.scope === 'mock');
  check('ALLOW discloses age_over_18', allow.insight.disclosed_claims?.includes('age_over_18'));

  const prompt = await callVerdict(client, HOSPITAL);
  check('hospital -> PROMPT', prompt.insight.verdict === 'PROMPT', prompt.insight.verdict);

  const deny = await callVerdict(client, UNKNOWN);
  check('unknown verifier -> DENY', deny.insight.verdict === 'DENY', deny.insight.verdict);
  check('DENY discloses nothing', Array.isArray(deny.insight.disclosed_claims) && deny.insight.disclosed_claims.length === 0);

  console.log('\nControlled-Insight boundary:');
  const allResponses = [allow.raw, prompt.raw, deny.raw].join('\n');
  for (const secret of FORBIDDEN_SUBSTRINGS) {
    check(`no leak of "${secret}"`, !allResponses.includes(secret));
  }
  const expectedKeys = [
    'decision_id', 'disclosed_claims', 'evaluated_at', 'policy_hash',
    'proven_claims', 'reason_codes', 'scope', 'verdict',
  ].sort();
  check(
    'response key set is exactly the whitelist',
    JSON.stringify(Object.keys(allow.insight).sort()) === JSON.stringify(expectedKeys),
    Object.keys(allow.insight).sort().join(','),
  );

  await client.close();

  console.log(`\n${failures === 0 ? 'SMOKE OK' : `SMOKE FAILED (${failures} assertion(s))`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(`\nSMOKE ERROR: ${err?.stack || err}\n`);
  process.exit(1);
});
