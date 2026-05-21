/**
 * @package @mitch/mcp-server
 * @description MCP server exposing the miTch policy engine to LLM agents.
 *
 * Transport: stdio (v1) — runs as a subprocess of the MCP client (e.g. Claude Desktop).
 * Keys, audit log and storage remain local; the agent only ever sees verdicts.
 *
 * IMPORTANT: All logging goes to stderr. stdout is reserved for the MCP protocol wire
 * format — any write to stdout outside of the SDK transport corrupts the session.
 *
 * See docs/mcp-server-architecture.md for the full design rationale, tool inventory
 * and open questions (§9) that need a decision before v2 (streamable HTTP).
 *
 * Usage (Claude Desktop claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "mitch": {
 *         "command": "node",
 *         "args": ["/path/to/mitch/src/packages/mcp-server/dist/index.js"]
 *       }
 *     }
 *   }
 *
 * Usage (development, before build):
 *   npx tsx src/packages/mcp-server/src/index.ts
 *
 * Smoke-test with MCP Inspector:
 *   npx @modelcontextprotocol/inspector node dist/index.js
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { fileURLToPath } from 'url';
import { registerEvaluateDisclosure } from './tools/evaluate-disclosure.js';

const SERVER_NAME = 'mitch-mcp-server';
const SERVER_VERSION = '0.0.1';

// ── Server factory (exported for testing) ───────────────────────────────────

export function createServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  // Register tools — add new tools here as they are implemented.
  // Order determines the tool list order returned to clients.
  registerEvaluateDisclosure(server);

  // Planned tools (not yet implemented — see docs/mcp-server-architecture.md §4):
  //   registerVerifyPresentation(server);    // mitch_verify_presentation
  //   registerCheckStatus(server);           // mitch_check_status
  //   registerListPolicies(server);          // mitch_list_policies
  //   registerGetPolicy(server);             // mitch_get_policy
  //   registerGetDecision(server);           // mitch_get_decision
  //   registerListDecisions(server);         // mitch_list_decisions
  //   registerExplainDenial(server);         // mitch_explain_denial
  //   registerAnchorStatus(server);          // mitch_anchor_status

  return server;
}

// ── Entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();

  // stderr only — never write to stdout outside the SDK transport
  process.stderr.write(`[mitch-mcp] starting ${SERVER_NAME}@${SERVER_VERSION} (stdio)\n`);

  await server.connect(transport);

  process.stderr.write(`[mitch-mcp] connected — waiting for requests\n`);
}

// Only run main() when this module is the entry point — not when imported (e.g. by tests).
// Compares the script path that Node was launched with against this module's own URL.
const isEntryPoint =
  process.argv[1] !== undefined && process.argv[1] === fileURLToPath(import.meta.url);

if (isEntryPoint) {
  main().catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[mitch-mcp] fatal: ${message}\n`);
    process.exit(1);
  });
}
