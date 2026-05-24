# Coding Agent Handoff - 2026-05-25

Status: handoff snapshot for the next coding agent
Scope: current architecture/process consolidation, dirty worktree, consent receipt work, OID4VP type workarounds, memory/doc updates

## Start Here

Read these first, in this order:

1. `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md`
2. `docs/DOCS_CANON.md`
3. `STATE.md`
4. `docs/BACKLOG.md`
5. `memory/projects/mitch-core.md`
6. `memory/context/stack.md`
7. `memory/glossary.md`

The key rule from the Privacy Firewall skill is:

```text
UNKNOWN => FAIL
```

Do not treat ambiguous architecture, untracked implementation, or conflicting documentation as "probably okay".

## Current Git State

As of this handoff:

- Branch: `master`
- Local branch is 2 commits ahead of `origin/master`
- Local HEAD before this handoff commit: `eb6d212 fix(wallet-pwa): avoid Vite config-bundle ENOENT on Windows`
- `origin/master`: `ae91f48 feat(wallet): paginate consent receipts`
- The worktree contained mixed docs, memory, consent-manager, wallet-pwa and OID4VP changes before this handoff was committed.

Important: if this file is read from a later commit, run:

```bash
git status --short --branch
git log --oneline --decorate --max-count=8
```

Use the actual command output over this historical note.

## What Was Consolidated

The previous architecture review work has been consolidated into:

- `docs/03-architecture/ARCHITECTURE_ANALYSIS_PROCESS_V2_2026-05-24.md`

That document is the current working standard for architecture analysis. It includes:

- verified repo/workspace state
- canonical documentation map
- ADR/Decision collection risks
- Privacy Firewall axioms
- deterministic reason codes
- actual code hot spots
- findings `F-ARCH-001` through `F-ARCH-010`
- a repeatable 8-step analysis process
- a nothing-forgotten checklist

## High-Priority Findings

### P0

- `F-ARCH-001`: dirty tree as architecture risk
- `F-ARCH-002`: ADR number collision and Decision drift
- `F-ARCH-003`: `policy_hash` semantic mismatch

### P1

- `F-ARCH-004`: `WalletService.ts` is a production-readiness blocker
- `F-ARCH-005`: `ConsentReceipt` is not canonical
- `F-ARCH-006`: ConsentReceipt export is not signed
- `F-ARCH-007`: selective claims are not true claim-level encryption yet
- `F-ARCH-008`: Pairwise DID failure currently continues soft

### P2

- `F-ARCH-009`: OID4VP local type augmentation workaround
- `F-ARCH-010`: documented package/LOC counts are stale

## Code Hotspots

Check these before changing architecture-sensitive behavior:

- `src/packages/policy-engine/src/engine.ts`
- `src/packages/policy-engine/src/allow-assertion.ts`
- `src/packages/policy-engine/src/conflict-resolver.ts`
- `src/packages/shared-types/src/policy.ts`
- `src/packages/shared-types/specs/decision_capsule.md`
- `src/apps/wallet-pwa/src/services/WalletService.ts`
- `src/packages/secure-storage/src/index.ts`
- `src/apps/wallet-pwa/src/consent-manager/types.ts`
- `src/apps/wallet-pwa/src/consent-manager/receipt-store.ts`
- `src/packages/oid4vp/src/demo-flow.ts`
- `src/packages/oid4vp/src/shared-crypto.d.ts`

Current verified size markers from the process document:

- `WalletService.ts`: 1395 lines
- `policy-engine/src/engine.ts`: 760 lines
- `secure-storage/src/index.ts`: 305 lines
- `shared-types/src/policy.ts`: 372 lines

## Architecture Decisions Needed

The next coding agent should not silently decide these while coding:

1. Should new architecture ADRs use `ARCH-ADR-XXX` and compliance ADRs use `COMP-ADR-XXX`?
2. Should `policy_hash` mean full `PolicyManifest` hash, with a new `rule_hash` for the matched rule?
3. Is Pairwise DID mandatory for all ALLOW/PROMPT proof flows?
4. Where is canonical `ConsentReceiptV1` defined?
5. Should ConsentReceipt export be signed by wallet identity/audit key?
6. Should `oid4vci` continue depending on `policy-engine`?
7. Which documented package/test counts are officially "last verified"?

## Recommended Next Work

1. Split the current changes into reviewable changesets if they are not already committed separately.
2. Update `docs/DOCS_CANON.md` and other entry docs when architecture process rules change.
3. Write a formal ADR for ConsentReceipt retention/export.
4. Fix `policy_hash` semantics or explicitly introduce `rule_hash`.
5. Canonicalize `ConsentReceiptV1`.
6. Move OID4VP local shared-crypto declarations into real shared exports.
7. Start `WalletService` decomposition with low-risk extraction:
   - `DemoSeedService`
   - `ConsentReceiptService`
   - `PresentationBuilder`
   - `CredentialRepository` port

## Verification Expectations

For docs-only changes:

```bash
git diff --check
```

For architecture-sensitive code changes:

```bash
pnpm --filter @mitch/policy-engine test
pnpm --filter @mitch/wallet-pwa test
pnpm --filter @mitch/oid4vp test
pnpm test
pnpm lint
```

Run narrower tests first when the tree is already mixed.
