# @askmi/mcp-server

> **Status:** Experimental — `evaluate_disclosure` wired to the policy engine over a non-authoritative **mock scope** by default, with an opt-in local JSON evaluation scope via `MITCH_WALLET_DB` (v0.2)

This package exposes the AskMI policy engine as a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server. It allows LLM agents (like Claude Desktop) to request disclosure evaluations without giving them access to raw credentials or keys.

## Features

- **Privacy Firewall for Agents:** Agents only see verdicts (`ALLOW`, `DENY`, `PROMPT`) and signed decision capsules.
- **Fail-Closed by Design:** Any ambiguous request results in a `DENY`.
- **Zero-Knowledge Ergonomics:** Agents interact with predicates (e.g., "is user over 18?") instead of PII.

## Current Status

`askmi_evaluate_disclosure` is **wired to `@askmi/policy-engine`** and returns real `ALLOW`/`DENY`/`PROMPT` verdicts.

By default it runs over a **non-authoritative mock scope** (`src/server-scope.ts`): synthetic policy + synthetic credential metadata. Every default response is tagged `scope: "mock"`. This honours the original freeze concern (no embedded default produces real decisions without an authorized policy) while enabling agentic integration. The thaw decision and its constraints are recorded in `docs/mcp-server-architecture.md` §11.

For local evaluation, set `MITCH_WALLET_DB` to a JSON evaluation-scope file containing:

```json
{
  "user_did": "did:example:holder",
  "policy": {
    "version": "local-1",
    "trustedIssuers": [],
    "rules": []
  },
  "credentials": []
}
```

Only policy data and `StoredCredentialMetadata[]` are loaded. Raw credentials, proofs, keys and claim values are out of scope. When `MITCH_WALLET_DB` is configured but invalid or unreadable, the tool fail-closes to `DENY` and returns `scope: "local"` with no disclosed claims; it does not silently fall back to mock.

All **read tools** (`get_decision`, `list_decisions`, `explain_denial`) remain frozen stubs pending a concrete audit use-case (architecture §10.4).

### Output: Controlled Insight
The agent never sees the full `PolicyEvaluationResult`. `src/sanitize.ts` reduces it to a whitelist object — `verdict`, `decision_id`, `policy_hash`, `reason_codes`, `disclosed_claims` (names only), `proven_claims` (names only), `scope`, `evaluated_at`. Credential ids, issuer DIDs, hashes, signatures and the pairwise DID are dropped.

### Implemented Tools
- `askmi_evaluate_disclosure`: Evaluates a verifier request against the policy engine (mock scope by default, local JSON scope when `MITCH_WALLET_DB` is set). Verdict + claim names only, fail-closed.

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
