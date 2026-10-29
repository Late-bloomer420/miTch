# Phase-0 Security Cleanup Forensics: Complete Record (2026-10-29)

**Scope:** Full forensic reconstruction of the 2026-03-12 cleanup sequence in
`src/packages/phase0-security/`, item-level inventory of what was lost, what
survives, and what is still relevant for the planned clean-up restoration.
**Companion record:** `docs/qa/PHASE0_SECURITY_METHOD_ASSESSMENT_2026-10-29.md`
(method-by-method assessment). This document covers the *history and inventory*;
that one covers the *code quality verdicts*.
**Reconstruction method:** git blob-hash comparison (`git rev-parse`), file
follow-history, and full diffs between every commit in the sequence. All
commit times below are from the original +0100 timezone.

## 1. The exact sequence (2026-03-12, five commits in 57 minutes)

| Time | Commit | Effect on the 5 root files |
|---|---|---|
| 21:31 | `01b94b1` chore: delete duplicate root-level .ts files | Deleted all 5 root files (−1957 lines) |
| 22:05 | `cb9bedd` feat(e2e): OID4VP flow (Block B) | No phase0-security changes |
| 22:27:30 | `897b226` fix: IndexedDB timeout on CI — inline fake-indexeddb, threads pool | **Re-added all 5 root files with byte-identical content** (blob `4b81021…` = `01b94b1^` blob). Also: deleted `test/setup.ts`, changed vitest pool forks→threads |
| 22:27:47 | `81d1672` Revert of `897b226` | **Final loss of the root files.** The revert was NOT a clean undo: it bundled ~513 lines of unrelated in-flight work (OID4VP tests, `App.tsx`, scenario-claims, CSP header) and permanently restored `test/setup.ts` + `pool: forks` |
| 22:28:17 | `38c1ade` fix: IndexedDB timeout — inline polyfill, drop global setup, threads | Re-applied the *other* variant of the CI fix: `setup.ts` removed from vitest config, pool threads; per-file inline `fake-indexeddb` imports |

Key forensic fact: `897b226` and `81d1672` are 17 seconds apart. The
"fix IndexedDB timeout" work apparently branched off a tree that still
contained the root files (branched before `01b94b1`), and the revert restored
*that* old tree state for phase0-security — re-deleting files that had been
intentionally cleaned up, while also pulling through unrelated work. This is a
textbook **branch-skew revert**, not a deliberate re-deletion.

The content was recoverable at every point until `81d1672`. After it, no
commit ever re-added the files. The `git log --follow` chain confirms:
`2b708e3` (import) → `e7f3aeb` (lint) → `d54bd7e`/`78a2bf0` (TODO impl) →
`01b94b1` (delete) → `897b226` (re-add) → `81d1672` (final delete).

## 2. Item-level inventory: lost vs. survives vs. relevant

### 2.1 Lost with NO surviving copy (the only true content loss)

From root `ADVANCED_SECURITY_HARDENING.ts` (790 lines, blob `4b81021…`):

1. **`export const HARDENING_CHECKLIST`** (lines 742–768): six ✅/⚠️
   capability lists per threat class (againstGoogle, againstMemoryDumps,
   againstNetworkSurveillance, againstSupplyChain, againstPhysicalSeizure,
   againstAI). Included honest limitations ("Cannot prove zeroization (JS
   limitation)", "Determined AI may still bypass").
2. **`RECOMMENDATION MATRIX`** (comment block, lines ~770–789): a
   4-level threat-tier table (Consumer / Journalist / Whistleblower /
   Government) mapping phase-0/1/2 countermeasures per tier.

Both verified absent from current `src/` and `docs/` (repo-wide grep, zero
hits). Relevance today: **medium** — the same tiered-threat idea exists
conceptually in `docs/MATURITY_AND_LIMITATIONS.md` and the QA assessment; the
matrix itself is Phase-0 concept work with pre-rebrand claims and must not be
restored as authoritative. A dated historical doc under `docs/context/` is the
only appropriate restoration (decision tracked in #243).

### 2.2 Lost as file, but survives elsewhere (NOT a loss)

- `MemoryHardeningProtection`, `NetworkHardeningProtection`,
  `SupplyChainHardeningProtection`, `PhysicalSeizureProtection`,
  `AIResistanceProtection` → rescued into `src/index.ts` (lines 771–1010),
  byte-near-identical to the root file.
- The **inline threat-model documentation** (nation-state / platform-vendor /
  seizure / supply-chain narrative, weaknesses per strategy) → survives almost
  verbatim in `src/packages/phase0-security/EXECUTIVE_SUMMARY.md` (the only
  later changes are the miTch→AskMI rebrand edits; verified by full diff).
  In particular the split-key 3-share design (OS keychain + YubiKey +
  password-manager) and all per-strategy pros/cons are documented there.
- `LocalAuditLog`, `EIDASComplianceChecker`, `VerifierDirectProtocol`,
  `integration-example` root files → all content lives on as the modular
  `src/` files; the root copies were true duplicates by then.

### 2.3 The root vs. src `ADVANCED_SECURITY_HARDENING` difference (pre-cleanup)

At `01b94b1^` the two versions diverged heavily (776 removed / 157 added lines
in diff): the root file was the original 790-line concept file with inline
threat commentary and the checklist/matrix; the 171-line src file is the
stripped, tested, refactored core (`PanicGuard`, modular
`UserDerivedKeyProtection`, GF(2^8) Shamir, `GoogleAppleBypass`). The 171-line
src file was NEVER a duplicate of the root file — "duplicate" in the commit
message was inaccurate, which is why the cleanup looked harmless but was not.

## 3. Test-wiring residue still live at HEAD (traced to the sequence)

- `vitest.config.ts`: `pool: 'forks'`, `fileParallelism: false`, 30s timeouts —
  introduced during this CI-timeout fight; `38c1ade` later settled it.
- `test/setup.ts`: no longer exists at HEAD — the file's deletion history is
  `897b226` (deleted) → `81d1672` (restored) → `38c1ade` (deleted, along with
  the `setupFiles` vitest reference); today's `vitest.config.ts` has no
  `setupFiles` entry. The surviving pattern is per-file inline `fake-indexeddb`
  imports in `eidas-compliance-checker.test.ts` and `phase0-security.test.ts`.
- Current evidence: 149/149 tests pass locally (5 files) after building
  `@askmi/shared-types` (2026-10-29 run).

## 4. What is still relevant for the planned restoration

Priority order for the clean-up (consolidated with #243):

1. **Consolidation of duplicate class implementations** (`index.ts` vs modular
   files, divergent `UserDerivedKeyProtection`/`SplitKeyProtection` APIs,
   hardcoded literal salt in `index.ts`) — real correctness/consistency issue.
2. **Fail-open labeling** of the demo placeholders (`verifyResponse`,
   unsigned `parseRequest`, cert-pinning stub, onion.to proxy,
   `isPlatformTrusted`, seizure/AI stubs) — aligns with fail-closed principle.
3. **Historical restoration decision** for checklist/matrix — dated doc only,
   marked superseded, if wanted at all.
4. **Share authentication (MAC) for SSS** if shares are stored in hostile
   locations; remove constant-time claims for `gf256Mul`.
5. No action needed: EXECUTIVE_SUMMARY threat narrative (already maintained),
   test wiring (stable and green).

## 5. Process lessons (for AGENTS/CONTRIBUTING, not code)

- A revert must be checked for **scope bleed**: `81d1672` bundled unrelated
  in-flight work; the commit title only mentions the IndexedDB fix.
- "Duplicate" claims in commit messages should be verified per blob before
  deletion; here two files with the same name were ~75% different.
- 17-second fix+revert pairs indicate an automation/agent loop reacting to CI
  without re-checking the working tree base — the same incident produced both
  `897b226` and `38c1ade` (two different "fixes" for the same timeout).
