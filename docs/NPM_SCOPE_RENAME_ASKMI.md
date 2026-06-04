# npm Scope Rename: `@mitch/*` → `@askmi/*` (published packages)

**Date:** 2026-06-04
**Branch:** `chore/askmi-scope-rename` (Scope A), `docs/current-state-alignment` (Scope B)
**Status:** Scope A done · Scope B done

## Context

The npm scope `@mitch` was **not available** for publishing. The three packages
that were published to npm therefore use the `@askmi` scope instead:

| npm package                     | version | status |
| ------------------------------- | ------- | ------ |
| `@askmi/shared-types`           | 0.1.0   | live   |
| `@askmi/shared-crypto`          | 0.1.0   | live   |
| `@askmi/revocation-statuslist`  | 0.1.0   | live   |

Verified locally on 2026-06-04 with:

```powershell
npm view @askmi/shared-types version
npm view @askmi/shared-crypto version
npm view @askmi/revocation-statuslist version
```

Because a package's `name` field **is** its import specifier in this pnpm
workspace, every consumer that imported `@mitch/{shared-types,shared-crypto,revocation-statuslist}`
would fail to resolve once those packages were renamed. The repository had to be
brought back into line with what is actually published.

This change was **re-derived fresh on `master`**, not merged from the
`rescue/second-pc-2026-06-04` branch — that branch bundles the rename with ~100
files of unrelated working state. Re-deriving keeps this diff minimal and auditable.

## Scope A — DONE (necessary for correctness)

Renamed `@mitch/*` → `@askmi/*` for the three published packages across **all
code and configuration** (everything required for the workspace to build, resolve,
and test correctly):

- The three packages' own `name` fields in `package.json`.
- `@askmi/shared-types` version aligned to the live npm version `0.1.0`.
- Every workspace `dependencies` reference (`workspace:*`) to those three.
- Every `import` / `from` in `.ts` / `.tsx` source and test files.
- `tsconfig.json` path references and `vite.config.ts` / `vitest.config.mjs` aliases.
- `pnpm-lock.yaml` (regenerated via `pnpm install --lockfile-only`).

**145 source/config files + the lockfile.** The source/config diff was limited to
the three published package names and the one `shared-types` version alignment.
Scope B documentation text was deliberately excluded from the first PR and
completed later in the Sprint 0 docs alignment pass.

### Verification (evidence)

Tests run via vitest (resolves workspace deps from source — proves the rename is
internally consistent):

| package                    | result            |
| -------------------------- | ----------------- |
| `revocation-statuslist`    | 26 passed         |
| `shared-crypto`            | 249 passed        |
| `audit-log`                | 30 passed         |
| `policy-engine`            | 303 passed (32 files) |

Additional checks:

- `rg '@mitch/(shared-types|shared-crypto|revocation-statuslist)' src package.json pnpm-workspace.yaml .github --glob '!**/*.md'` returns no code/config hits.
- `git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,tab-in-indent,cr-at-eol diff --cached --check` is clean. Plain `git diff --check` is noisy on this Windows checkout because global `core.autocrlf=true` treats CRLF as trailing whitespace in the displayed patch, while the repo has `.gitattributes` `eol=lf`.

Note: I did not run a full repo build in this pass. Local `dist/` artifacts are
gitignored and must be rebuilt after switching branches (`pnpm -r build`); stale
`dist/` output is the main way a consumer can transiently reference the old
`@mitch/` name even after the source rename is correct.

## Scope B — DONE (docs-only consistency)

The following documentation/Markdown files had references to the old `@mitch/*`
names for the three published packages. They did not affect compilation,
resolution, or tests, so they were intentionally left out of Scope A and handled
as a narrow docs cleanup during Sprint 0. Only these three package names were
changed; this was not a full project rebrand.

```
README.md
REFACTORING_ROADMAP.md
SPRINT_PLAN.md
STATE.md
archive/PHASE3_COMPLETION_REPORT.md
archive/prototypes/mi.login/workflow_audit.md
docs/03-architecture/mvp/ADR-003_Revocation_Strategy.md
docs/03-architecture/mvp/ADR-005_Metadata_Minimization_Strategy.md
docs/03-architecture/mvp/ADR-007_AI_Orchestrator_Integration.md
docs/03-architecture/mvp/ADR-008_Batch_Credentials_Strategy.md
docs/03-architecture/mvp/ADR-011_Claim_Level_Encryption_Strategy.md
docs/03-architecture/mvp/ADR-012_ISO_18013-5_mdoc_Offline_Verification_Strategy.md
docs/NIGHTLY_REPORT.md
docs/SESSION_HISTORY.md
docs/_core/06_OPEN_DECISIONS.md
docs/archive/E2E_VALIDATION_REPORT.md
docs/archive/VALIDATION_REPORT.md
docs/b2b-use-cases/01_module_fintech_kyc.md
docs/b2b-use-cases/02_module_igaming_compliance.md
docs/b2b-use-cases/03_module_supply_chain_credentials.md
docs/b2b-use-cases/04_module_healthcare_ehds.md
docs/b2b-use-cases/README.md
docs/compliance/EUDI_CIR_MATRIX.md
docs/compliance/SECURITY_TARGET_CC_READY.md
docs/mcp-server-architecture.md
docs/modules/social-login-privacy.md
docs/ops/TRUST_ANCHOR_ARCHITECTURE.md
docs/pilot/findings/DRY_RUN_01_FINDINGS.md
docs/specs/109_Presentation_Binding_AntiReplay_Spec_v1.md
docs/specs/111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md
docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md
docs/vision/MITCH_AI_GUARDIAN.md
src/packages/policy-engine/README.md
```

Verification after Scope B:

- `rg '@mitch/(shared-types|shared-crypto|revocation-statuslist)' . --glob '!node_modules/**' --glob '!dist/**'` returns only this historical mapping note.

## Explicitly NOT changed

All **other** `@mitch/*` packages (e.g. `@mitch/policy-engine`, `@mitch/oid4vp`,
`@mitch/wallet-pwa`, `@mitch/predicates`, …) keep their names. Only the three
packages actually published under `@askmi` were renamed. A full `@mitch → @askmi`
rebrand of every package is a separate, larger decision and is **out of scope** here.
