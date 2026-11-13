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

**History and test-wiring verification:** 2026-11-13, repository revision
`d5ae4ea`, using Git tree IDs, diffs and file inspection on Windows/PowerShell.
**Test evidence:** Historical 2026-10-29 observation; tests not rerun for the
2026-11-13 history verification.

## 1. The exact sequence (2026-03-12, five commits in 57 minutes)

| Time | Commit | Effect |
|---|---|---|
| 21:31 | `01b94b1` chore: delete duplicate root-level .ts files | Intentionally deleted all 5 root files (1957 lines). Whole commit: 49 insertions / 2082 deletions, including lockfile changes. The duplicate-content premise was inaccurate for `ADVANCED_SECURITY_HARDENING.ts`. |
| 22:05 | `cb9bedd` feat(e2e): OID4VP flow (Block B) | Added OID4VP/App.tsx work; no phase0-security changes. |
| 22:27:30 | `897b226` fix: IndexedDB timeout on CI | Re-added all 5 root files with their pre-cleanup content, removed recent OID4VP/App.tsx work and other changes, deleted `test/setup.ts`, and switched forks to threads. Whole commit: 1978 insertions / 800 deletions. |
| 22:27:47 | `81d1672` Revert of `897b226` | Clean, exact revert: 800 insertions / 1978 deletions. Restored `cb9bedd`'s tree, including its OID4VP/App.tsx work and intentional absence of the root files. Temporarily restored `test/setup.ts` and forks. |
| 22:28:17 | `38c1ade` fix: IndexedDB timeout | Removed `test/setup.ts` and its config reference, switched forks to threads, and added inline fake-indexeddb imports to `local-audit-log.test.ts`. |

Decisive evidence: `git diff 897b226^ 81d1672` is empty. Both trees have ID
`34e2629518bfa6060f52487f40bd218e331f96aa`. The revert's line statistics are
the exact inverse of `897b226`; its restored application changes are not
unrelated work bundled into the revert.

The skewed change was `897b226`, not its revert. Its diff reintroduced files
intentionally removed by `01b94b1` and undid recent application work. Git
establishes these changes, but the 17-second interval does not establish an
automation loop or the author's working-tree provenance.

The root files remain recoverable from Git history after their deletion.
Their sequence is `01b94b1` (delete) → `897b226` (re-add) → `81d1672`
(restore pre-fix absence). Absence from a later checkout is not loss of the
historical blobs.

## 2. Item-level inventory: lost vs. survives vs. relevant

### 2.1 Absent from the assessed checkout, recoverable from Git history

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

## 3. Test wiring at the reviewed revision

At `d5ae4ea`, inspected on 2026-11-13:

- `vitest.config.ts` uses `pool: 'threads'`, `fileParallelism: false`, and
  30s hook/test timeouts. `38c1ade` switched forks to threads 30 seconds
  after the revert.
- `test/setup.ts` is absent, and there is no `setupFiles` entry. Its sequence
  is `897b226` (deleted) → `81d1672` (restored) → `38c1ade` (deleted).
- Inline fake-indexeddb imports exist in `eidas-compliance-checker.test.ts`,
  `phase0-security.test.ts`, and `local-audit-log.test.ts`; the last is the
  test file changed by `38c1ade`.
- Historical observation retained: 149/149 tests passed locally (5 files)
  after building `@askmi/shared-types` in the 2026-10-29 run. This is not a
  fresh test result for `d5ae4ea`.

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
   test wiring (historical passing result in §3; not rerun for the 2026-11-13
   history verification).

## 5. Process lessons (for AGENTS/CONTRIBUTING, not code)

- Verify duplicate-content claims by blob hash before deletion. The root and
  modular `ADVANCED_SECURITY_HARDENING.ts` were different files in content.
- Review the complete fix diff for accidental removal of recent work:
  `897b226` undid application work outside its stated IndexedDB scope.
- Compare a revert with the intended pre-fix tree. `81d1672` passed that
  check exactly; its large diff is not evidence of unrelated additions.
- Commit timing alone does not prove an automation loop or a stale checkout.
