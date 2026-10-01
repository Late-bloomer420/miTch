# Security Audit Remediation Roadmap

Date: 2026-10-01
Status: active triage plan.

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
- inspect PR #152 and re-apply only the shell-injection-safe evidence-runner
  change if still relevant;
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

- run `pnpm evidence`;
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
2. create a fresh branch for the first selected fix;
3. land it with targeted tests and required CI.
