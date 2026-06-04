# Sprint 0: Repo Truth Alignment

**Date:** 2026-06-04
**Status:** In progress
**Branch target:** `docs/current-state-alignment`

## Purpose

Bring miTch's operational truth, planning truth, and agent-facing context back into
one coherent map before the next feature sprint.

This sprint is intentionally not a product-feature sprint. It exists because the
repository currently contains multiple overlapping status, session, task, and
agent-memory surfaces. Some are current, some are historical, and some are
agent-specific. Future agents can easily pick the wrong source and make changes
from stale assumptions.

## Initial Findings

### F0-01: Canonical status sources exist but drifted

`docs/DOCS_CANON.md` defines a sensible hierarchy:

- `STATE.md` for operational health.
- `docs/BACKLOG.md` for task tracking.
- `docs/SESSION_HISTORY.md` for completed sessions.
- `docs/specs/SPECS_STATUS_INDEX.md` for spec classification.

However, the actual files are not fully aligned. Examples found on 2026-06-04:

- `STATE.md` is dated 2026-06-02 and does not include PR #66 / npm `@askmi`
  alignment.
- `docs/BACKLOG.md` starts with old open P0 video-gap rows, but later marks
  related work such as `G-100` and `G-110` as done.
- `docs/SESSION_HISTORY.md` records Session 13 but not the 2026-06-04 npm scope
  and repo hygiene work.
- Test counts differ across `README.md`, `STATE.md`, `AGENTS.md`, and older
  task files.

### F0-02: Agent-facing files compete with each other

Tracked agent/context files currently include:

- `AGENTS.md`
- `CLAUDE.md`
- `CLAUDE_TASKS.md`
- `GEMINI.md`
- `.agent/skills/**`
- `.codex/agents/miTchDevelopmentAgent.toml`

Local ignored agent surfaces also exist:

- `.agents/`
- `.claude/`
- `.qodo/`

This is not automatically wrong, but the repo needs a clear rule for what is
authoritative and what is historical. In particular, `CLAUDE_TASKS.md` is a
Session 10 task file with old direct-to-master instructions and an old
`D:/Mensch/miTch` working directory. It should not be treated as current runbook
material.

### F0-03: Workspace memory and repo memory are mixed conceptually

Some repo documents reference workspace-only memory paths such as
`memory/miTch_security_patterns_memory.md`. That can be useful for local context,
but it is not portable repo documentation unless the boundary is explicit.

The current OpenClaw workspace memory also contains one path drift noted during
this discovery: the human mentioned `.aaCodeing/miTch`, but the actual local
checkout on this machine is `C:\Users\Lenovo\.aaCoding\miTch`.

### F0-04: `docs/qa` exists but is not canonically classified

The human clarified that the intended example was the `qa` folder, not `qr`.

Local checks on 2026-06-04 found:

- `docs/qa/MIT-10-demo-evidence.md`
- `docs/qa/MIT-10-wallet.png`
- `docs/qa/WALLET_RECOVERY_RC_2026-06-04.md`

These are valuable QA/evidence artifacts, not random notes. They validate local
demo and wallet recovery flows, but `docs/DOCS_CANON.md` does not currently
define where QA evidence belongs or how it relates to `STATE.md`,
`docs/SESSION_HISTORY.md`, `docs/ops/EVIDENCE_PACK_P0.md`, and pilot findings.

Observed drift examples:

- `MIT-10-demo-evidence.md` is dated 2026-05-25 and mentions 26 `@askmi/*`
  packages and prebuilt `dist/`.
- `WALLET_RECOVERY_RC_2026-06-04.md` is newer, references commit `f2a6ae1`, and
  records `pnpm test` as 45/45 tasks plus 5174/3004/3005 as canonical ports.
- `STATE.md` is still dated 2026-06-02 and does not explicitly point to
  `docs/qa` as the current QA evidence surface.

Sprint 0 now classifies `docs/qa` as date-specific QA evidence in
`docs/DOCS_CANON.md`; the newest evidence should be linked from `STATE.md` when
it represents the current operating state.

### F0-05: npm scope alignment is technically done, documentation cleanup remains

PR #66 merged the necessary code/config rename for the three published packages:

- `@askmi/shared-types`
- `@askmi/shared-crypto`
- `@askmi/revocation-statuslist`

`docs/NPM_SCOPE_RENAME_ASKMI.md` deliberately defers Scope B: Markdown/docs-only
references to the old names. Sprint 0 should either complete that narrow cleanup
or explicitly schedule it, but it must not turn into a full project rebrand.

### F0-06: Branch and local clone sprawl need a rule, not a blind cleanup

Many local and remote branches still exist, including phase/release/recovery and
rescue branches. Some are useful audit history; some may be stale. The agreed
principle remains: keep `master` clean and integrate only small reviewed diffs.

Sprint 0 should document branch handling rules, but should not delete branches
without an explicit separate decision.

## Proposed Sprint 0 Scope

### In Scope

1. Update `STATE.md` to the true current operational state as of 2026-06-04.
2. Update `docs/SESSION_HISTORY.md` with the npm scope PR and repo hygiene events.
3. Reconcile `docs/BACKLOG.md` contradictions around completed vs open video-gap
   items.
4. Update `AGENTS.md` and `CLAUDE.md` so future agents use current package names,
   current commands, and current repo rules.
5. Move or clearly mark stale session task files such as `CLAUDE_TASKS.md` as
   historical if they are no longer active.
6. Complete narrow Scope B docs cleanup for only:
   - `@askmi/shared-types` -> `@askmi/shared-types`
   - `@askmi/shared-crypto` -> `@askmi/shared-crypto`
   - `@askmi/revocation-statuslist` -> `@askmi/revocation-statuslist`
7. Add or update a short "where things go" rule:
   - operational status
   - backlog/task tracking
   - session history
   - agent instructions
   - local/private workspace memory
8. Classify `docs/qa` in the docs canon and connect its evidence files to the
   relevant status/session records.

### Out of Scope

- Feature work such as Identity Firewall, Proof Randomization, or partner
  onboarding.
- Full `@askmi/*` -> `@askmi/*` rebrand.
- Deleting branches or old checkouts.
- Editing private OpenClaw workspace bootstrap/reference files as part of the
  repo PR.
- Rewriting historical docs just to make old claims sound current.

## Proposed Acceptance Criteria

- `docs/DOCS_CANON.md` and the actual repo layout agree.
- A new agent can read `AGENTS.md` and avoid stale package names, stale direct
  master instructions, and stale workspace paths.
- `STATE.md` reflects the current `master` state after PR #66.
- `docs/BACKLOG.md` no longer presents the same epic as both open P0 and done
  without explanation.
- Stale session files are either archived or clearly marked as historical.
- `docs/qa` has an explicit role in the repo documentation map.
- Narrow npm Scope B docs cleanup is complete or intentionally deferred with a
  clear reason.
- No feature code changes are included in the Sprint 0 PR.

## Open Questions Before Execution

1. Should `CLAUDE_TASKS.md` remain in the repo root as active instructions, or
   move to `docs/archive/` like the older Session 7 task file?
2. Should `.agent/skills/**` remain tracked as repo-local skills, or should all
   agent skills move under one canonical directory?
3. Should repo docs continue to reference local workspace `memory/*` files, or
   should those references become non-portable/local notes only?

## Recommended Next Step

Ask for approval on this scoped Sprint 0. If approved, create branch
`docs/current-state-alignment` and make the cleanup as a single documentation and
agent-context PR.
