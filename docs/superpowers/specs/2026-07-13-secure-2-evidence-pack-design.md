# SECURE-2 — Internal Evidence Pack + Runnable Evidence Harness

**Status:** Design — awaiting approval
**Date:** 2026-07-13
**Author:** Claude (Opus 4.8) with J F M / AskMI
**Track:** SECURE (second of two: SECURE-1 gap closure ✅ merged #132 → **SECURE-2 evidence pack** → then ADOPT track)
**Relates to:**
- `docs/compliance/SECURITY_TARGET_CC_READY.md` (Common Criteria Security Target)
- `docs/03-architecture/mvp/ADR-009_Threat_Model.md` (STRIDE table + gap analysis, reconciled by SECURE-1)
- `docs/ops/EVIDENCE_PACK_P0.md`, `docs/compliance/EUDI_CIR_MATRIX.md`, `docs/qa/` (dated evidence records)
- `docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md`, `docs/qa/SECURE_1_FINDINGS_REGISTER.md`

---

## 1. Context

SECURE-1 closed the code-fixable security gaps and reconciled the threat model. AskMI now has strong but **scattered** security evidence: a Security Target, a reconciled STRIDE threat model, a EUDI-CIR matrix, dated QA records, P0 evidence, and runbooks — with no single navigable entry-point, no responsible-disclosure policy, and no way to *prove on demand* that each security claim still maps to a passing test.

The user's goal for SECURE-2 is **internal completeness**: one coherent, honest, self-audit-ready evidence pack, ready to hand to any external party later. The user chose a **full runnable evidence harness** (not docs-only) so claims are provable, not just asserted.

## 2. Goal & Non-Goals

**Goal:** A single evidence pack anchored by a **runnable harness** that executes a claim→test map and emits a timestamped, integrity-hashed evidence report, plus the consolidating docs and the responsible-disclosure policy.

**Non-Goals (explicit):**
- The actual external evaluation — **GAP-4 remains open**; this pack *prepares* for it, it is not the review.
- New product security features or code changes to the wallet/policy/crypto surface (SECURE-1 did that).
- Formal Common Criteria evidence classes (ADV/AGD/ATE/AVA) — out of scope for "internal completeness".
- Cryptographic report signing as a hard requirement — provided as an **optional flag only** (default hash-only, no key management).
- Modifying any existing security test to fit the harness — the harness maps to tests **as they are**.

## 3. Architecture

Two parts: a **harness** (code, TDD'd) and the **evidence docs** (consolidation + gap-fill).

### 3.1 Harness — private workspace package `@askmi/evidence`

A private (unpublished, `"private": true`) workspace package under `src/packages/evidence/`, so it is testable with the repo's Vitest setup like every other package. Three focused units:

**a. Manifest** — `src/manifest.ts` exporting a typed array `EVIDENCE_CLAIMS: EvidenceClaim[]`, where:
```ts
export interface EvidenceClaim {
  id: string;                    // e.g. "STRIDE-T-1", "SECURE1-F04", "GDPR-ERASURE"
  claim: string;                 // human-readable guarantee
  category: 'stride' | 'fail-closed' | 'gdpr' | 'eudi-cir' | 'unlinkability';
  package: string;               // '@askmi/policy-engine'
  testFile: string;              // path relative to the package, e.g. 'src/__tests__/ehds-geo-scope.test.ts'
  testNamePattern?: string;      // optional vitest -t filter
  residual?: { reason: string }; // present ⇒ intentionally NOT proven by a test (e.g. GAP-1 TEE, GAP-4 external review)
}
```
The initial manifest covers: the SECURE-1 fixes (F-01/F-02/F-03/F-04/F-16/F-18/F-14 + GAP-3), the core ADR-009 STRIDE rows that have `belegt` test references, and the residuals (GAP-1, GAP-4, and the documented-residual findings). It is the single source linking a *claim* to its *proof*.

**b. Runner** — `src/runner.ts` exporting `runEvidence(claims, opts): Promise<EvidenceResult[]>`:
- For each non-residual claim: resolves the test file to an absolute path; if it does **not exist → `status: 'FAIL'`, reason `'test file not found'`** (fail-closed; this catches stale/fabricated citations automatically). Then runs it via `vitest run <file> [-t pattern]` scoped to the claim's package, capturing exit code + pass/fail/skip counts.
- Residual claims are recorded `status: 'RESIDUAL'` with the reason — never silently "passed".
- Any runner-level exception for a claim → `status: 'ERROR'` with the message. Never throws out of `runEvidence`.

**c. Report generator** — `src/report.ts` exporting `generateReport(results, opts): { markdown: string; json: object; hash: string }`:
- Deterministic Markdown + JSON: per-claim `id/claim/category/status/counts`, totals (proven / failed / error / residual), the toolchain versions, and a **SHA-256 hash** over the canonicalized JSON (integrity). Timestamp is provided by the caller (injectable) so report bodies are deterministic in tests.
- Optional `sign?: (bytes) => Promise<string>` hook (default undefined). When the CLI passes `--sign`, it wires shared-crypto Ed25519; otherwise hash-only. Signing is out of the harness core — the core only accepts an optional signer.

**d. CLI** — `src/cli.ts` (`bin`), invoked by a root script `pnpm evidence`:
1. run `runEvidence(EVIDENCE_CLAIMS)`, 2. `generateReport(...)` with `new Date()`, 3. write `docs/qa/evidence-reports/EVIDENCE_<UTC-ISO>.md` + `.json`, 4. print a console summary, 5. exit non-zero if any claim is `FAIL`/`ERROR` (residuals do not fail the run).

### 3.2 Evidence docs (consolidation + gap-fill)

- **`docs/security/README.md`** — the pack entry-point ("start here"): links Security Target, ADR-009 threat model, the claim→test manifest + latest report, EUDI-CIR matrix, P0 evidence, runbooks, and the residuals register; states how to run `pnpm evidence`.
- **`SECURITY.md`** (repo root) — responsible-disclosure / vulnerability-reporting policy (reporting channel, scope, safe-harbor intent, response expectations). Standard OSS/security convention; currently missing.
- **`docs/security/RESIDUALS.md`** — honest open-items register consolidating GAP-1 (TEE / browser RAM), GAP-4 (external review), and the SECURE-1 documented-residual findings; each with why it is not closed and what would close it. The pack must not overclaim.
- **Reproducible build/verify** — a section in `docs/security/README.md`: clone → `pnpm install` → `pnpm build` → `pnpm test` → `pnpm evidence`, with expected results (46+ turbo tasks green; evidence report all-proven).

## 4. Data flow

`manifest.ts` (claims) → `runner.runEvidence` (executes mapped tests, fail-closed) → `EvidenceResult[]` → `report.generateReport` (Markdown + JSON + SHA-256) → CLI writes `docs/qa/evidence-reports/EVIDENCE_<ts>.{md,json}` + console summary + exit code.

## 5. Error handling (fail-closed)

- Missing/renamed test file → `FAIL` (not skip). Renaming a test without updating the manifest breaks the evidence run — intended.
- Test run error / non-zero exit → `FAIL`; unexpected runner exception → `ERROR`. Neither is ever counted as proven.
- Manifest schema violation (missing required field, unknown category) → hard throw **before** any test runs.
- Residual claims are explicit `RESIDUAL`, never conflated with proven.
- `pnpm evidence` exits non-zero if any `FAIL`/`ERROR` — so it is CI-usable later.

## 6. Testing (TDD)

The harness is TDD'd like any package:
- **Manifest schema validation** — a valid claim passes; a claim missing `testFile`/`package` or with an unknown `category` throws.
- **Runner fail-closed** — a claim pointing at a nonexistent test file yields `FAIL 'test file not found'` (this test also guards against fabricated citations); a claim pointing at a real passing test yields `PASS`; a residual claim yields `RESIDUAL` without running anything.
- **Report determinism** — same results + same injected timestamp → identical Markdown/JSON/hash; a changed result → changed hash.
- **Signing hook** — when a signer is provided, the report includes the signature; when absent, hash-only.
- Runner tests that actually shell out use one tiny real fixture test (a trivially-passing and a nonexistent path), not the whole suite, to stay fast.

## 7. Definition of Done

- [ ] `@askmi/evidence` package builds and its own tests pass (adds one turbo task: 46→47).
- [ ] `pnpm evidence` runs and writes a report to `docs/qa/evidence-reports/`; every non-residual claim in the initial manifest is `PASS`; residuals listed honestly; exit 0.
- [ ] A baseline evidence report committed.
- [ ] `docs/security/README.md`, `SECURITY.md`, `docs/security/RESIDUALS.md` written; entry-point links resolve.
- [ ] The manifest's `testFile` references all exist (guaranteed by a green `pnpm evidence`).
- [ ] Full `pnpm test` (47/47 turbo) + `pnpm lint` (0 errors) + `pnpm guard:rebrand` green.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Harness shelling out to vitest is slow / flaky | Runner scopes to a single package+file per claim; harness self-tests use one tiny fixture, not real suites. `pnpm evidence` is a separate command, not added to the default `pnpm test` path. |
| Manifest drifts as tests are renamed | That is the point — a stale `testFile` makes `pnpm evidence` FAIL, surfacing the drift (same class of bug SECURE-1 reconciliation hit). |
| Scope creep into signing / key management | Signing is an optional injected hook, default off; no key management in the harness core. |
| Adding a package trips the rebrand/CI guards | Package is `@askmi/evidence`, `"private": true`, on the `@askmi/*` scope; follows existing package conventions. |
| Report files churn git | Reports live under `docs/qa/evidence-reports/` as dated artifacts (like existing dated QA records); only a baseline is committed, later runs are on-demand. |

## 9. Successor

After SECURE-2, the **ADOPT** track (separate spec → plan → build): "Sign in with AskMI" integration kit (G-150), partner/verifier onboarding registry (G-160), reference integration. F-14's now-real credential signature verification is a foundation the ADOPT verifier kit can build on.
