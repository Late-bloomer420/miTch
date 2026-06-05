# Old Branch Audit - 2026-06-05

**Baseline:** `master` at `16f61bb` after PRs #70, #71, and #72.
**Goal:** Review old/local/agent branches before deleting, cherry-picking, or opening new PRs.
**Rule:** Do not merge old branches directly. Review against current AskMI `master`, secret-scan, and extract only scoped changes.

## Current PR State

- Open GitHub PRs: none.
- Recent PRs #66-#72 are merged.
- `master` checks were green after #72.

## Not-Merged Branch Inventory

Local branches not merged into `master`:

- `analysis/sovereignty-center-ui-only`
- `backup/pre-sync-2026-05-28`
- `codex/mit21-sovereign-deployment`
- `codex/repo-local-skills-20260525`
- `codex/verifier-privacy-fail-closed`
- `feat/controlled-insight`
- `feat/wallet-dynamic-credentials-sync`
- `recovery/wallet-v1-rc-final`
- `rescue/review-mit21-2026-06-04`

Remote branches not merged into `origin/master`:

- `origin/analysis/sovereignty-center-ui-only`
- `origin/final-ai-guardian-vision`
- `origin/recovery/wallet-v1-rc-final`
- `origin/rescue/second-pc-2026-06-04`

## Block 1: Sovereignty / MIT-21 / VRN

Branches reviewed:

- `analysis/sovereignty-center-ui-only`
- `codex/mit21-sovereign-deployment`
- `rescue/review-mit21-2026-06-04`

### 1. `analysis/sovereignty-center-ui-only`

Diff against `master`:

- Adds only `docs/tasks/SOVEREIGNTY_CENTER_UI_ONLY_ANALYSIS.md`.
- No code changes.
- Quick secret scan of the diff produced no hits.

Assessment:

- Not dangerous, but mostly historical now.
- The most important finding from this doc is already reflected on `master`: `InsightAggregator` exists and tests cover current `snake_case` audit metadata via `DataFlowService`.
- Still useful as provenance for why the Sovereignty Center must aggregate normalized `DataFlowTransaction` data instead of parsing raw audit metadata directly.

Recommendation:

- Keep as documentation only if rewritten to current AskMI naming and marked as historical/pre-implementation analysis.
- Do not merge as-is because it references stale `@mitch/*` package names and an old base commit.

### 2. `codex/mit21-sovereign-deployment`

Diff against `master`:

- 47 files changed, about 2,293 insertions and 775 deletions.
- Adds Docker/Caddy deployment stack, verification scripts, local LOTL fixture, trust-list/status resolvers, wallet credential renderer components, consent-modal copy changes, OID4VCI batch issuance tests, and compliance/ops docs.
- Contains many stale active identifiers: `@mitch/*`, `did:mitch`, `mitch.demo`, and old workflow package names.

Assessment:

- Valuable ideas exist, but the branch predates the AskMI rebrand and the later Sprint 01/02 fixture work.
- Direct merge would break the active rebrand guard and likely reintroduce stale contracts.
- The deployment stack and trust-list resolver work should be treated as source material, not a merge candidate.

Recommended extraction candidates:

- Deployment strategy docs and verify scripts, after AskMI environment/name rewrite.
- Trust-list resolver concept, but only after comparing with current `LOTL_TRUST_LIST_FIXTURE`, `ASKMI_DEMO_ISSUER`, and StatusList helpers.
- Consent-modal distinction between proven claims and raw disclosed claims, preserving current UX copy and tests.
- Credential renderer/card UI only if it still matches the current wallet data model.

Recommendation:

- Do not merge.
- Create one small PR per extracted concept after rebrand alignment and tests.

### 3. `rescue/review-mit21-2026-06-04`

Diff against `master`:

- Contains the MIT-21/sovereign-deployment work plus wider historical changes.
- Non-Paperclip diff still touches 55 files.
- Also includes tracked `paperclip-home` history removals: 1,895 files and a known sensitive path `paperclip-home/instances/default/secrets/master.key`.

Assessment:

- This branch is quarantine/source-material only.
- It should never be merged directly.
- It is useful for remembering what was removed and what old recovery/compliance claims existed, but its history is too risky and too stale for integration.

Recommendation:

- Do not merge.
- Do not open PR from this branch.
- Extract only specific commits/files after comparing with `codex/mit21-sovereign-deployment` and current `master`.

## Block 1 Verdict

We did almost miss `analysis/sovereignty-center-ui-only`: it is small and remote, and it explains the correct recovery rule for Sovereignty Center.

But the core implementation part of that analysis is already present on `master`:

- `src/packages/data-flow/src/InsightAggregator.ts`
- `src/packages/data-flow/src/__tests__/InsightAggregator.test.ts`
- `docs/tasks/SPRINT_RECOVERY_ENHANCEMENT.md`

What remains open from this block:

- Sovereignty Center UI component and app integration are still not on `master`.
- VRN/reputation sensor work is still planned, not implemented.
- Deployment/TSL resolver work exists only in stale old branches and must be re-cut if still desired.

## Next Audit Order

1. `analysis/sovereignty-center-ui-only`: decide whether to port the analysis doc as historical context or close/delete the branch.
2. `feat/controlled-insight`: compare with current `InsightAggregator` and Sovereignty Center plan.
3. `feat/wallet-dynamic-credentials-sync`: check whether dynamic credential-card work overlaps with old `CredentialRenderer`.
4. `recovery/wallet-v1-rc-final` and `origin/rescue/second-pc-2026-06-04`: verify whether any recovery fixes remain absent from `master`.
5. `codex/verifier-privacy-fail-closed`: check if its fail-closed behavior is already covered by Sprint 01/02 smoke tests.
6. `codex/repo-local-skills-20260525`: docs/agent-skill-only review.
7. `backup/pre-sync-2026-05-28` and `origin/final-ai-guardian-vision`: historical/value scan only.
