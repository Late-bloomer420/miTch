# SEC-AUDIT-2 batch: fast-uri pin — 2026-10-25

Scope: one dependency family — `fast-uri` (ajv's URI resolver). Branch
`fix/sec-audit-2-fast-uri`, stacked on `fix/sec-audit-2-body-parser` (PR #227)
to avoid lockfile conflicts. Node v24.16.0, pnpm 9.15.9, Windows.

## Exposure

`fast-uri@3.1.x < 3.1.7` had **7 high advisories** (DoS/ReDoS-class and parsing
corruption fixes through 3.1.7), consumed via `ajv` — the runtime
`@askmi/mcp-server` chain (`@modelcontextprotocol/sdk` > ajv) plus ajv in
`verifier-demo` tooling.

## Change

`package.json` → `pnpm.overrides`: `"fast-uri@<3.1.7": ">=3.1.7 <4"`. All
instances resolve to **3.1.9**; the `<4` bound prevents a major jump (same
discipline as the body-parser pin).

## Audit deltas (live `pnpm audit --json`, 2026-10-25)

- Before this batch: high **48** (after PR #227's body-parser fix).
- After: high **41**, critical 0 — all 7 `fast-uri` advisories cleared.
- Cumulative across SEC-AUDIT-2 batches ①+③: high 49 → 41.

## Verification (local)

- `pnpm build` green; `pnpm guard:rebrand` green.
- `@askmi/mcp-server` tests green (11).

Residual high advisories remain open under the roadmap: the MCP SDK
`>=1.32.0` runtime bump (also owns body-parser@2, hono, ip-address, zod) and
the dev/test tooling batch (undici, brace-expansion, js-yaml, browserslist,
vite) plus the `pnpm` CLI devDep in `@askmi/evidence`. This is not a
clean-audit claim; CI on the PR head is the next evidence.
