/**
 * @package @askmi/mcp-server
 * @description MCP server exposing the AskMI policy engine to LLM agents.
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
 *       "AskMI": {
 *         "command": "node",
 *         "args": ["/path/to/AskMI/src/packages/mcp-server/dist/index.js"]
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
import { registerEvaluateDisclosure } from './tools/evaluate-disclosure.js';

const SERVER_NAME = 'AskMI-mcp-server';
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
  //   registerVerifyPresentation(server);    // askmi_verify_presentation
  //   registerCheckStatus(server);           // askmi_check_status
  //   registerListPolicies(server);          // askmi_list_policies
  //   registerGetPolicy(server);             // askmi_get_policy
  //   registerGetDecision(server);           // askmi_get_decision
  //   registerListDecisions(server);         // askmi_list_decisions
  //   registerExplainDenial(server);         // askmi_explain_denial
  //   registerAnchorStatus(server);          // askmi_anchor_status

  return server;
}

// ── Entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();

  // stderr only — never write to stdout outside the SDK transport
  process.stderr.write(`[AskMI-mcp] starting ${SERVER_NAME}@${SERVER_VERSION} (stdio)\n`);

  await server.connect(transport);

  process.stderr.write(`[AskMI-mcp] connected — waiting for requests\n`);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[AskMI-mcp] fatal: ${message}\n`);
  process.exit(1);
});
