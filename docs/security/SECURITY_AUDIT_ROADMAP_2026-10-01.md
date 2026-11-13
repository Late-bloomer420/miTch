# Security Audit Remediation Roadmap

> **Refresh (2026-10-14):** #152 is already merged and its shell-free runner must be preserved.
> #150/#151 remain open, and #141 contains unmerged security work. EV-05 demonstrates that master CI can exit 0 on synthetic critical findings;
> current registry advisory counts were not re-measured in this documentation pass. #170–#173 own the new concrete slices.
> [Finding index](REPO_EVIDENCE_STATUS_2026-10-14.md) qualifies only overlapping integration/claim scopes; existing component evidence and the original intake facts remain intact.

Date: 2026-10-01
Status: active triage plan.

## Scoped audit gate checkpoint — 2026-10-24

#185 owns the minimum critical audit gate and dependency triage, assigned to
@Late-bloomer420 with a **2026-10-26** review/triage target. A separate patch
proposes critical=0 enforcement in both audit workflows, with command/registry/
report errors also denied. High counts remain visible; high enforcement remains
open work. [Dated local evidence](../qa/SECURITY_AUDIT_GATE_2026-10-24.md)
records 17 gate regressions and the current live audit (146 total, 52 high,
1 critical), which the proposed gate rejects. This does not remediate dependencies,
close #185/EV-05, or establish a merged CI result. #193 lifecycle work stays separate.

## SEC-AUDIT-2 batch checkpoint — 2026-10-25 (body-parser@1.x pin)

First SEC-AUDIT-2 runtime batch landed as one dependency family: the
`body-parser <1.20.9` high advisory (DoS via trailing bytes after a number) in
the **Express 4 runtime chain** of `issuer-mock`, `verifier-backend`,
`verifier-demo` and `@askmi/connect` is cleared by a `pnpm.overrides` pin
`body-parser@<1.20.9 >=1.20.9 <2` (upper bound prevents a major jump that would
break Express 4). The Express 5 `body-parser@2` advisories stay open and are
owned by the `@modelcontextprotocol/sdk >=1.32.0` bump (batch ②). Live audit:
**high 49 → 48, critical 0**. [Dated local
evidence](../qa/SECURITY_AUDIT_2_BODY_PARSER_2026-10-25.md). Residual high
batches (fast-uri via ajv, undici/brace-expansion/js-yaml tooling, pnpm CLI
devDep in `@askmi/evidence`, MCP SDK runtime bump, zod) remain open.

## SEC-AUDIT-2 batch checkpoint — 2026-10-25 (fast-uri pin)

Second SEC-AUDIT-2 runtime batch: `fast-uri@<3.1.7` → `>=3.1.7 <4` clears all
**7 high advisories** in ajv's URI resolver (runtime `@askmi/mcp-server` chain
plus verifier-demo tooling ajv); all instances resolve to 3.1.9. Cumulative
highs across batches ①+③: **49 → 41, critical 0**. [Dated local
evidence](../qa/SECURITY_AUDIT_2_FAST_URI_2026-10-25.md). Open batches: the
`@modelcontextprotocol/sdk >=1.32.0` runtime bump (owns body-parser@2, hono,
ip-address, zod), the dev/test tooling batch (undici, brace-expansion,
js-yaml, browserslist, vite), and the `pnpm` CLI devDep in `@askmi/evidence`.

## Purpose

This document turns the current security-audit backlog into small, reviewable
remediation slices. The goal is to reduce real risk without mixing unrelated
security, dependency and product work into one oversized PR.

## Current Intake

Observed on 2026-10-01:

- GitHub Dependabot still reports dozens of open alerts on `master`;
- `pnpm audit --json` reports no critical advisories, but a large set of high,
  moderate and low advisories across transitive tooling and selected runtime
  dependencies;
- open security-focused PRs already exist for:
  - PR #151 — decision id randomness;
  - PR #152 — evidence runner command-injection hardening;
  - PR #140 — PostCSS dependency update.

This roadmap is not an external penetration test. GAP-4 in
[`RESIDUALS.md`](RESIDUALS.md) remains open until a third party reviews the
codebase.

## Remediation Order

### SEC-AUDIT-1 — Review and land small code security PRs

Priority: P0.

Scope:

- inspect PR #151 and re-apply only the secure-randomness change if still
  relevant;
- preserve the merged PR #152 shell-free runner; do not reapply or regress it;
- close EV-05 by making advisory threshold and audit errors fail closed in the integrated workflows;
- reject stray/generated files that do not belong in the codebase.

Acceptance:

- changes are based on current `master`, not stale branch state;
- targeted tests for each changed package pass;
- `pnpm guard:rebrand` passes;
- required GitHub checks pass after merge.

### SEC-AUDIT-2 — Dependency alert batch 1: direct and high-signal transitive fixes

Priority: P0/P1.

Initial candidates:

- `undici` to a patched `7.29.1+`;
- `hono` / `@hono/node-server` to patched versions through the MCP SDK path;
- `fast-uri` through `ajv`;
- `js-yaml` through ESLint config tooling;
- `postcss`, `vite`, `nanoid`, `browserslist`, `baseline-browser-mapping`;
- `form-data`, `qs`, `body-parser`, `ip-address`, `brace-expansion`.

Acceptance:

- one dependency family per PR unless the lockfile solver naturally groups
  them;
- explain runtime vs dev/test-only exposure;
- `pnpm audit --json` count decreases or the residual is documented;
- build/test/rebrand checks pass.

### SEC-AUDIT-3 — Evidence harness and security-pack freshness

Priority: P1.

Scope:

- deliver #173 exact source/profile and persisted-byte binding, then run the applicable harness;
- refresh the latest evidence report if code changed;
- update `docs/security/README.md` current-status dates and counts;
- ensure newly added `@askmi/connect` claims enter the harness only after the
  code slice exists.

Acceptance:

- evidence report has zero failed claims;
- residual claims remain explicit and do not masquerade as passes.

### SEC-AUDIT-4 — Residual hardening candidates

Priority: P1/P2.

Scope:

- F-20 pairwise DID generation should surface an explicit
  `unlinkabilityWarning` instead of silent omission;
- F-19 audit persistence failures need a production-storage path before pilot;
- F-15 break-glass should get a signed emergency-context token before any
  health pilot;
- F-05/F-06/F-22 should stay residual until real L2 anchoring is in scope.

Acceptance:

- each residual either has a concrete hardening PR or remains explicitly open
  with rationale in `RESIDUALS.md`.

## Working Rules

- Do not batch public-preview/tunnel/exposure work into security remediation.
- Do not merge stale bot branches blindly; inspect, cherry-pick or reimplement
  against current `master`.
- Prefer a smaller PR that closes one real finding over a broad lockfile churn
  PR with unclear blast radius.
- Keep `@askmi/connect` security requirements in sync with
  [`../tasks/ADOPT_1_SDK_API_SHAPE.md`](../tasks/ADOPT_1_SDK_API_SHAPE.md).

## First Action

Start with SEC-AUDIT-1 after ADOPT-1.2 is accepted:

1. review PR #151 and #152 against current `master`;
2. use #170–#173 and EV-05 as named intake; create a fresh focused branch for a selected code fix;
3. land it with targeted tests and required CI.
