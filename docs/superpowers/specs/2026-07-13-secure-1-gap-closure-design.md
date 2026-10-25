# SECURE-1 — Close the Closable Security Gaps + Fail-Closed Bug Sweep

**Status:** Design — awaiting approval
**Date:** 2026-07-13
**Author:** Claude (Opus 4.8) with J F M / AskMI
**Track:** SECURE (first of two: SECURE-1 gap closure → SECURE-2 external-audit evidence pack)
**Relates to:**
- `docs/03-architecture/mvp/ADR-009_Threat_Model.md` (STRIDE — GAP-1..GAP-4)
- `docs/BACKLOG.md` → S-10 (Formal Threat Model), Phase 3 Security Hardening
- `docs/qa/WEBAUTHN_FAIL_CLOSED_2026-07-12.md`, BACKLOG update 2026-07-13 (GDPR false-success + `signData` key-name bugs)

---

## 1. Context

AskMI is at `v1.0-RC (Pilot Readiness)`: 98% technical EUDI CIR (52/53, the one gap being *external* Common Criteria certification), 46/46 turbo test tasks, 1820+ tests, fail-closed policy engine, WebAuthn hardware-bound identity, crypto-shredding, pairwise-DID unlinkability.

The user's goal for this track is **"ready for others to adopt + maximally secure."** SECURE is being built first (a hardened core before new attack surface is exposed by the ADOPT track), and within SECURE, this sub-project (**SECURE-1**) is built before the evidence pack (**SECURE-2**) so the pack documents a *true, fixed* state.

The threat model (ADR-009) documents four gaps:

| Gap | Nature | Closable by code? |
|---|---|---|
| GAP-1 | Browser JS/V8 gives no physical RAM wipe; `TypedArray.fill(0)` is best-effort | **No** — needs TEE (ADR-010, deferred). Document only. |
| GAP-2 | "Recovery on device-loss not implemented (no remote-wipe, no guardian)" | **Stale claim** — `shared-crypto/src/recovery.ts` implements real Shamir Secret Sharing (2-of-3, GF(2⁸)) Trust-Circle recovery, wired into `App.tsx` + `WalletService.ts`, with QA evidence `WALLET_RECOVERY_RC_2026-06-04.md`. Needs **reconciliation**, not new code. |
| GAP-3 | Timing side-channel on the anti-oracle path; only jitter exists, no constant-time guarantee | **Partially** — see §4 honesty boundary. |
| GAP-4 | No external security review | **No** — human precondition. Prepared for in SECURE-2, not performed here. |

Two recent real bugs (fixed 2026-07-13) prove the security-critical surface still hides defects worth systematically hunting:
- **False-success:** `requestDataErasure` / `reportRelyingParty` returned `success: true` and wrote audit `SENT` **without ever sending** the signed proof token (network POST commented out / missing).
- **Contract mismatch:** `signData()` read `auditLog.privateKey` via cast while keys are stored under `auditPrivateKey` → the whole erasure/report path threw "Identity keys not available" and was effectively dead.

Both belong to identifiable bug *classes*. SECURE-1 hunts those classes systematically.

## 2. Goal & Non-Goals

**Goal:** Close every *code-fixable* security gap on AskMI's security-critical surface, each proven with a regression test, and reconcile the threat model to the resulting true state.

**Non-goals (explicit — do not do in SECURE-1):**
- GAP-1 (TEE / hardware RAM protection).
- GAP-4 (external security review — human; prepared for in SECURE-2).
- The ADOPT track (integration kit, partner registry).
- Any new user-facing UX or features.
- BBS+ multi-show unlinkability (U-10–U-13) and the mdoc-AV / ECDSA-ZKP path (G-100.5 / #97) — both consciously deferred elsewhere.
- The SECURE-2 evidence pack itself (Security Target consolidation, `SECURITY.md`, reproducible-build packaging).

## 3. Scope surface (in / out)

**In scope (audited deeply):**
- `src/apps/wallet-pwa/src/services/WalletService.ts` (and the repositories it delegates to)
- `src/packages/policy-engine/src/` — `engine.ts`, `rate-limiter.ts`, `proof-fatigue.ts`, `jurisdiction.ts`, `allow-assertion.ts`, `anti-oracle` path, `kpi.ts`
- `src/packages/audit-log/`
- `src/packages/oid4vp-verifier/` — response verification path
- `src/packages/webauthn-verifier/`
- `src/packages/shared-crypto/` — `recovery.ts`, `IdentityKeyGuardian.ts`, `SoftwareKeyGuardian.ts`, key-guardian interfaces

**Out of scope (not audited in this pass):** the remaining ~23 packages, the two other apps' frontends beyond their security paths, protocol packages not on the decision/verification path. If the sweep surfaces a concrete cross-package security thread, it is recorded as a finding but only fixed if it lies on the in-scope decision/verification/crypto path.

## 4. Approach: Sweep → Fix → Reconcile

### Part C — Sweep (discovery, first)

Systematic audit of the in-scope surface for these bug classes:

1. **Silent failure / false-success** — `success: true` / `return true` / resolved promises returned before the operation actually succeeded; audit records written as `SENT`/`OK` without the effect.
2. **Fail-closed violations** — any path that defaults to ALLOW / accept / success on error, empty input, or ambiguity. (AskMI invariant: ambiguity → DENY.)
3. **Swallowed errors** — `catch` blocks that discard the error and continue; security-relevant `async` calls not `await`ed; unhandled rejection paths.
4. **Contract / key-name mismatch behind casts** — `as any` / structural casts on security objects that can silently read `undefined` (the `signData` class).

**Method:** targeted reads + `grep` for the patterns above (`catch`, `success: true`, `return true`, `as any`, `|| ALLOW`, non-awaited async on security calls), producing a **findings register** — each finding with: location, class, a short PoC description, **severity × confidence**, and a disposition of `fix` / `documented-residual` / `not-a-bug`. Low-confidence or non-security findings are recorded and dispositioned, not silently dropped.

The sweep is run **inline** (no subagent dispatch), going deep on the in-scope surface rather than shallow across all packages.

### Part B — GAP-3 (constant-time anti-oracle), folded into Fix

Audit the policy decision path (`engine.ts` + deny-code mapping + any credential/user-existence check) for **secret-dependent branching** a verifier could time — e.g. "no such user" returning at a different point than "policy denied". The existing anti-oracle already collapses 27+ internal deny-codes to ≤4 verifier-visible buckets (content channel); GAP-3 is the **timing** channel.

**Deliverables:**
1. Eliminate any timing-observable early return / short-circuit that correlates with a secret (user existence, credential presence, specific deny reason).
2. A **statistical timing-variance regression test** asserting the per-call mean latency across allow / deny / no-user paths stays within a bound, amortized over N iterations — same amortization style as the existing `anti-oracle.test.ts` (`< 0.1ms` per-call average over 2000 iterations) so it is not itself load-flaky.
3. Keep existing network-timing jitter (U-23).

**Honesty boundary (stated in the spec and carried into the doc):** true constant-time execution is **unattainable** in a browser JS/V8 runtime (JIT, GC, deopt). SECURE-1 delivers *eliminated secret-dependent branching + a tested variance bound + retained jitter + a documented residual*, not mathematical constant-time. GAP-3 moves from "open" to "mitigated, with documented residual," not "eliminated."

### Part A — Reconcile (docs, last)

After all fixes land and the suite is green:
1. **ADR-009 threat model** — correct GAP-2 (recovery IS implemented via SSS Trust Circle → reclassify to closed/residual with the code + QA references); update GAP-3 to "mitigated + documented residual" citing the new test; add STRIDE rows for any bug found+fixed in the sweep; update the Fail-Closed Acceptance table and Change Log.
2. **`docs/BACKLOG.md`** — S-10 progress; note the sweep findings closure.
3. **`STATE.md`** — operational security-posture line.
4. **`docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md`** — dated evidence record: findings register with dispositions, per-fix test references, GAP-3 test evidence, full-suite/lint/guard results.

## 5. TDD discipline (hard rule)

Every code fix follows the project TDD skill:
**RED** (write a failing test reproducing the finding) → **verify RED** (fails for the right reason, not a typo) → **GREEN** (minimal fix) → **verify GREEN** (passes + no regressions) → **REFACTOR** (stay green).

No production code changes without a failing test first. Part A (documentation) is exempt from RED/GREEN but every claim it makes must cite a test that exists and passes.

## 6. Error-handling philosophy

Fail-closed everywhere. Every finding's fix must default to **DENY / failure / reject** on any error, empty input, or ambiguity — never to ALLOW / success / accept. A fix that merely "handles" an error by continuing is not acceptable; the error must propagate to a closed outcome with an auditable reason.

## 7. Definition of Done

- [ ] Findings register complete; every finding dispositioned (`fix` / `documented-residual` / `not-a-bug`).
- [ ] Every `fix` finding closed with a regression test that failed before the fix and passes after.
- [ ] GAP-3 timing-variance regression test present and green; secret-dependent branching on the decision path eliminated or shown absent.
- [ ] ADR-009 reconciled to true state (GAP-2 corrected, GAP-3 updated, new STRIDE rows, change log).
- [ ] `BACKLOG.md` + `STATE.md` aligned; dated QA evidence record written under `docs/qa/`.
- [ ] `pnpm test` (46/46 turbo tasks) + `pnpm lint` (0/0) + `pnpm guard:rebrand` all green.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Sweep finds a defect whose fix touches a public package API | No breaking API changes without explicit approval (CLAUDE.md). Record as a finding; pause for approval before changing a public contract. |
| Timing-variance test is load-flaky in CI | Amortize over N iterations (proven pattern in `anti-oracle.test.ts`); assert on per-call *mean*, not a single measurement. |
| Sweep scope creep across all 29 packages | Scope surface (§3) is fixed; off-surface findings are recorded but only fixed if on the decision/verification/crypto path. |
| A "finding" is actually intended behavior | `not-a-bug` disposition with rationale; no change made. |
| GAP-3 over-promises constant-time | Honesty boundary (§4) is explicit in both spec and reconciled doc; residual documented. |

## 9. Successor

**SECURE-2** (separate spec → plan → build): consolidate the external-audit evidence pack — Security Target + reconciled threat model + test-evidence index + `SECURITY.md` responsible-disclosure + reproducible build/verify steps — packaged for an external CC/pentest lab (addresses GAP-4's *preparation*, not the review itself). Then the **ADOPT** track.
