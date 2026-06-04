# @mitch/mcp-server

MCP server that exposes the miTch policy engine to LLM agents via the
Model Context Protocol. Stdio transport, runs as a local subprocess of
an MCP client (Claude Desktop, Claude Code, Cowork, MCP Inspector).

> **Status (2026-05-22): FROZEN STUB.**
> The package is wired and registered, but every tool intentionally
> returns `DENY` with reason code `NOT_IMPLEMENTED`. Do not implement
> tool bodies without satisfying the unfreeze triggers below. The
> architecture rationale is in
> [`docs/mcp-server-architecture.md`](../../../docs/mcp-server-architecture.md).

## Why this is a stub

The freeze is a deliberate design choice, not unfinished work. Two open
questions block real implementation:

1. **Policy source ambiguity.** Without a concrete consumer it is
   unclear whether policies should be embedded in the binary, loaded
   from a file path, or passed in per-call by the agent. An embedded
   default would produce real `ALLOW`/`DENY` decisions against an
   unauthorized policy — that violates the project's fail-closed
   contract before the first byte of business logic ships.
2. **Read-side value proposition.** For audit-style queries
   (`mitch_list_decisions`, `mitch_get_decision`,
   `mitch_explain_denial`) the simpler path is "export
   `AuditLogExport.json`, drop it into a local LLM chat." The MCP
   detour only earns its complexity when one of the unfreeze triggers
   fires.

## Unfreeze triggers

Implement tool bodies only when a concrete user story arrives that
matches one of these. Numbers are guidance, not gates — what matters is
that the trigger is documented in the PR.

- **(a) Audit-log volume.** Export-size > ~10k entries and token
  efficiency starts to matter for the consumer LLM.
- **(b) External reporting.** Reports go to third parties and
  hash-chain verification is a customer-facing argument (so a
  structured `mitch_anchor_status` call beats "trust the JSON").
- **(c) Recurring audit routine.** A workflow emerges that re-runs
  the same structured query frequently, so freetext-parsing of the
  export becomes the bottleneck.

Until then the rule is: **add tools, keep stubs, ship nothing
verifiable as a real verdict.**

## What is implemented

- ✅ Stdio entry point with proper stderr-only logging (`src/index.ts`).
- ✅ Tool factory exported for in-memory testing (`createServer`).
- ✅ Full Zod input schema for `mitch_evaluate_disclosure` — the API
  contract is locked in, only the handler body waits.
- ✅ One stub tool: `mitch_evaluate_disclosure` →
  `{ verdict: "DENY", reason_codes: ["NOT_IMPLEMENTED"], stub: true }`.
- ✅ Vitest test suite covering: tool is listed, stub shape is
  well-formed, decision IDs are unique per call, invalid input is
  rejected by the schema.

## What is deliberately not implemented

The other eight tools from
[architecture §4](../../../docs/mcp-server-architecture.md#4-tool-inventar-v1)
are commented out in `src/index.ts` rather than missing — that way the
intended surface stays visible without producing live verdicts:

- `mitch_verify_presentation`
- `mitch_check_status`
- `mitch_list_policies`
- `mitch_get_policy`
- `mitch_get_decision`
- `mitch_list_decisions`
- `mitch_explain_denial`
- `mitch_anchor_status`

## Adding a new tool (when a trigger fires)

1. Update [`docs/mcp-server-architecture.md`](../../../docs/mcp-server-architecture.md)
   §10 with the user story and trigger reference.
2. Add a stub file under `src/tools/` that registers the tool with its
   full Zod schema and returns `NOT_IMPLEMENTED`.
3. Uncomment the registration line in `src/index.ts`.
4. Add at least the four baseline tests (listed, well-formed,
   unique-id, invalid-rejected). Mirror
   `src/__tests__/evaluate-disclosure.test.ts`.
5. Only now wire the handler body. Behind a feature flag if the wiring
   touches `@mitch/policy-engine`, so the stub remains the default
   until the wiring is reviewed.

## Local usage

Build:

```bash
pnpm --filter @mitch/mcp-server build
```

Run tests:

```bash
pnpm --filter @mitch/mcp-server test
```

Smoke-test with MCP Inspector:

```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "mitch": {
      "command": "node",
      "args": ["/absolute/path/to/miTch/src/packages/mcp-server/dist/index.js"]
    }
  }
}
```

## Security notes (apply once tools are real)

- **stdout is reserved for the MCP wire protocol.** All logging goes to
  stderr. A single `console.log` corrupts the session.
- **Never expose raw credentials, keys, or audit entries** through tool
  results. Verdicts, reason codes, and signed capsules only.
- **Rate-limit per agent and per verifier** using
  `@mitch/policy-engine`'s existing rate limiter — do not roll a new
  one here.
- **Validate every input** through Zod. The schemas in
  `src/tools/*.ts` are the authoritative API contract.
- **Errors return structured reason codes**, never stack traces.
