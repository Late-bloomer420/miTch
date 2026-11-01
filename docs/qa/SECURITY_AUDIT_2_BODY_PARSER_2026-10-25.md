# SEC-AUDIT-2 batch: body-parser@1.x runtime pin — 2026-10-25

Scope: one dependency family — `body-parser` 1.x in the Express 4 runtime
chain. Branch `fix/sec-audit-2-body-parser`, base master, Node v24.16.0,
pnpm 9.15.9, Windows. No dependency other than this pin changed.

## Exposure (runtime, not dev-only)

`body-parser@1.20.4` was a runtime transitive dependency via `express@4.22.1`
in `issuer-mock`, `verifier-demo` (root + backend), and `@askmi/connect`
(devDependency there). The advisory is a Denial-of-Service via trailing bytes
after a number (JSON parsing), fixed in **1.20.9**.

## Change

`package.json` → `pnpm.overrides`: `"body-parser@<1.20.9": ">=1.20.9 <2"`.

The `<2` upper bound is load-bearing: an unbounded `>=1.20.9` override lets the
lockfile solver jump to `body-parser@2.x` (observed during this work: all
instances resolved to 2.2.2), which is the Express 5 API line and would change
behavior for Express 4 apps. With the bound, Express 4 chains resolve to
**1.20.9** and the Express 5 chain (via `@modelcontextprotocol/sdk` >
`express@5.2.1`) keeps `body-parser@2.2.2`, whose advisories are owned by the
SDK >=1.32.0 bump (SEC-AUDIT-2 batch ②).

## Audit deltas (live `pnpm audit --json`, 2026-10-25)

- Before: high **49**, critical 0.
- After: high **48**, critical 0 — the `body-parser <1.20.9` advisory is gone.
- Remaining `body-parser` advisories: 2 (both `>=2.0.0 <2.4.0` range, via the
  MCP SDK Express 5 chain) — batch ② scope, not claimed fixed here.

## Verification (local)

- `pnpm build` green; `pnpm guard:rebrand` green.
- Runtime consumers' tests green: `issuer-mock` 16, `@askmi/connect` 66,
  `verifier-backend` 208 (all suites, package-level).

This is a dependency remediation record, not a clean-audit or
production-readiness claim. CI on the PR head is the next evidence.
