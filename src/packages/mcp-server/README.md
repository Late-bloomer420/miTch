# @askmi/mcp-server

> **Status:** Experimental / Frozen Stub (v0.1)

This package exposes the AskMI policy engine as a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server. It allows LLM agents (like Claude Desktop) to request disclosure evaluations without giving them access to raw credentials or keys.

## Features

- **Privacy Firewall for Agents:** Agents only see verdicts (`ALLOW`, `DENY`, `PROMPT`) and signed decision capsules.
- **Fail-Closed by Design:** Any ambiguous request results in a `DENY`.
- **Zero-Knowledge Ergonomics:** Agents interact with predicates (e.g., "is user over 18?") instead of PII.

## Current Status

The server is currently in a **frozen stub phase**. While the architecture is defined, most tools are stubs returning `DENY` with a `NOT_IMPLEMENTED` reason. This is a deliberate design choice to prevent the accidental creation of valid decisions without a fully authorized policy source.

### Implemented Tools
- `askmi_evaluate_disclosure`: Evaluates a verifier request against the local policy engine.

### Planned Tools (See `docs/mcp-server-architecture.md`)
- `askmi_verify_presentation`
- `askmi_check_status`
- `askmi_list_policies`
- `askmi_get_decision`
- ...and more.

## Usage

### Claude Desktop
Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "AskMI": {
      "command": "node",
      "args": ["/path/to/AskMI/src/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Development
```bash
# Start with tsx
npx tsx src/packages/mcp-server/src/index.ts

# Inspect with MCP Inspector
npx @modelcontextprotocol/inspector dist/index.js
```

## Security & Privacy
- **Transport:** Currently supports `stdio` for local process communication.
- **Data Minimization:** Raw credentials never leave the AskMI boundary.
- **Audit:** Every call is logged to the local `@askmi/audit-log`.

## Architecture
For the full design rationale, tool inventory, and security considerations, see [docs/mcp-server-architecture.md](../../../docs/mcp-server-architecture.md).
