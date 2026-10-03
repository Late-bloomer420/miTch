# SECURE-1 — Security Gap Closure + Fail-Closed Bug Sweep — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every code-fixable security gap on AskMI's security-critical surface — each proven with a regression test — and reconcile the ADR-009 threat model to the resulting true state.

**Architecture:** Discovery-driven, three phases in strict order: **Sweep** (audit the in-scope surface → a findings register), **Fix** (one TDD cycle per `fix`-dispositioned finding, plus GAP-3 timing hardening), **Reconcile** (rewrite the threat model + backlog/state + QA evidence to the true, fixed state). The fix tasks in Phase 3 are *instantiated from the register produced in Phase 1* using the fully-specified TDD template in this plan — they cannot be enumerated before the sweep runs, by design.

**Tech Stack:** TypeScript (monorepo, pnpm workspaces), Vitest (`environment: 'node'` for packages, `jsdom` for `wallet-pwa`), Turbo v2. No new runtime dependencies.

## Global Constraints

- **Fail-closed principle:** ambiguous / error / empty-input evaluations → DENY (policy) or failure (actions). Never default to ALLOW/success. *(verbatim: CLAUDE.md "Fail-closed principle: Ambiguous policy evaluations → DENY. Never default to ALLOW.")*
- **No breaking changes to public package APIs without explicit approval.** A finding whose fix requires a public-signature change PAUSES for approval — it is not silently changed.
- **DecisionCapsule fields:** `verdict`, `decision_id`, `policy_hash` (NOT `policy_manifest_id`).
- **Conventional commits:** `fix:`, `test:`, `docs:`, `chore:`.
- **Code style:** Prettier (single quotes, 2-space indent, trailing commas es5, 100 print width). ESLint `@typescript-eslint/no-explicit-any: warn`; unused vars prefixed `_`.
- **TDD is mandatory** for every production-code change: RED → verify RED → GREEN → verify GREEN → REFACTOR. No production code without a failing test first.
- **Green bar before "done":** `pnpm test` (46/46 turbo tasks) + `pnpm lint` (0 errors, 0 warnings) + `pnpm guard:rebrand` all pass.
- **Scope surface (audited deeply; nothing outside is modified):** `wallet-pwa/src/services/WalletService.ts` (+ its repositories), `policy-engine/src` (`engine.ts`, `rate-limiter.ts`, `proof-fatigue.ts`, `jurisdiction.ts`, `allow-assertion.ts`, `deny-reason-codes.ts`, anti-oracle path), `audit-log`, `oid4vp-verifier` (response verification), `webauthn-verifier`, `shared-crypto` (`recovery.ts`, `IdentityKeyGuardian.ts`, `SoftwareKeyGuardian.ts`, key-guardian interfaces).
- **Out of scope (do not touch):** GAP-1 (TEE), GAP-4 (external review), ADOPT track, new UX/features, BBS+ (U-10–13), mdoc-AV / #97.

---

## Phase 0 — Baseline

### Task 0: Confirm a green baseline and open the findings register

**Files:**
- Create: `docs/qa/SECURE_1_FINDINGS_REGISTER.md` (working artifact; folded into the final QA record in Phase 4)

**Interfaces:**
- Produces: `SECURE_1_FINDINGS_REGISTER.md` with the finding schema every later task reads.

- [ ] **Step 1: Verify the suite is green before touching anything**

Run: `pnpm test`
Expected: 46/46 turbo tasks pass. If not green, STOP — do not start on a red baseline; report the failure.

- [ ] **Step 2: Verify lint + rebrand guard are clean**

Run: `pnpm lint` then `pnpm guard:rebrand`
Expected: lint 0 errors / 0 warnings; guard passes.

- [ ] **Step 3: Create the findings register with its schema**

Create `docs/qa/SECURE_1_FINDINGS_REGISTER.md`:

```markdown
# SECURE-1 Findings Register

**Started:** 2026-07-13
**Baseline:** `pnpm test` 46/46 green, lint 0/0, guard green (Task 0).

Each finding:

| ID | File:line | Class | Description (1 line) | Severity | Confidence | Disposition |
|----|-----------|-------|----------------------|----------|------------|-------------|

- **Class:** `false-success` | `fail-closed-violation` | `swallowed-error` | `contract-mismatch`
- **Severity:** `high` (auth/crypto/disclosure bypass) | `med` (audit/integrity) | `low` (defense-in-depth)
- **Confidence:** `high` (PoC-able) | `med` (needs runtime confirmation) | `low` (suspicious, unverified)
- **Disposition:** `fix` (Phase 3 task) | `documented-residual` (can't fix in scope, note why) | `not-a-bug` (rationale)

## Findings

_(populated by Task 1)_
```

- [ ] **Step 4: Commit**

```bash
git add docs/qa/SECURE_1_FINDINGS_REGISTER.md
git commit -m "chore(secure-1): open findings register on a verified-green baseline"
```

---

## Phase 1 — Sweep (discovery)

### Task 1: Audit the in-scope surface and populate the findings register

This task is **investigation**, not code. Its deliverable is a complete, dispositioned findings register. It is not "done" until every in-scope file below has been read and every hit from the pattern grep has been dispositioned in the register.

**Files:**
- Modify: `docs/qa/SECURE_1_FINDINGS_REGISTER.md` (fill the Findings table)
- Read (no modification in this task): every file in the scope surface (Global Constraints).

**Interfaces:**
- Consumes: the finding schema from Task 0.
- Produces: a Findings table where each row's `Disposition` is one of `fix` / `documented-residual` / `not-a-bug`. Each `fix` row becomes exactly one Phase-3 task.

- [ ] **Step 1: Pattern grep across the scope surface**

Run each of these (via the Grep tool or `rg`), scoped to the surface paths, and record every hit for triage:

```
# false-success: success/true returned near an un-awaited or commented-out effect
rg -n "success:\s*true|return true" src/apps/wallet-pwa/src/services src/packages/policy-engine/src src/packages/audit-log src/packages/oid4vp-verifier src/packages/webauthn-verifier src/packages/shared-crypto/src

# swallowed errors: empty or comment-only catch blocks
rg -n -U "catch\s*\([^)]*\)\s*\{\s*(//[^\n]*)?\s*\}" src/apps/wallet-pwa/src/services src/packages/policy-engine/src src/packages/audit-log src/packages/oid4vp-verifier src/packages/webauthn-verifier src/packages/shared-crypto/src

# contract-mismatch behind casts on security objects
rg -n "as any|as unknown as" src/apps/wallet-pwa/src/services src/packages/policy-engine/src src/packages/audit-log src/packages/oid4vp-verifier src/packages/webauthn-verifier src/packages/shared-crypto/src

# fail-open smells: default ALLOW/accept, non-awaited security async
rg -n "ALLOW|accept|verified\s*=\s*true|\.then\(|void " src/packages/policy-engine/src/engine.ts src/packages/oid4vp-verifier/src src/packages/webauthn-verifier/src
```

- [ ] **Step 2: Read each in-scope file end-to-end for the four bug classes**

For each file in the scope surface, read it fully and check specifically:
  - Does any function report success/ALLOW/verified before the effect (network POST, signature verify, key destroy, audit append) is confirmed?
  - Does any `catch` continue as if nothing failed on a security-relevant path?
  - Does any security-relevant `async` call go un-`await`ed (fire-and-forget)?
  - Does any `as any` / structural cast let a property read silently return `undefined` (the `signData` → `auditPrivateKey` class)?

- [ ] **Step 3: Disposition every candidate in the register**

For each hit/observation, add a row with severity, confidence, and disposition. Write a one-line rationale for every `not-a-bug` and `documented-residual`. Do not drop anything silently — a swept-and-cleared line is evidence.

- [ ] **Step 4: Commit the completed register**

```bash
git add docs/qa/SECURE_1_FINDINGS_REGISTER.md
git commit -m "test(secure-1): complete security sweep findings register"
```

**Gate:** review the register with the user before starting Phase 3. Every `fix` row → one Task in Phase 3. If the register has zero `fix` rows, Phase 3 is skipped and the plan proceeds to Phase 2 (GAP-3) then Phase 4.

---

## Phase 2 — GAP-3 timing hardening

### Task 2: Anti-oracle timing-variance regression guard + branching audit

The policy engine's `evaluate()` (`engine.ts:165`) has DENY returns at very different call depths — `UNKNOWN_VERIFIER` at line 202 (early), `CLAIM_NOT_ALLOWED` after the requirement loop (line 267/273, late) — all funneling through the single `private async result()` exit at `engine.ts:694`. The existing anti-oracle test (`__tests__/anti-oracle.test.ts:204`) holds a placeholder: `it('DOCUMENTED: response-level timing padding is required for Phase 6', () => { expect(true).toBe(true); })`. This task replaces that placeholder with a real regression guard and documents the honest residual.

**Honesty boundary (must appear verbatim in the QA record, Phase 4):** true constant-time execution is unattainable in a browser JS/V8 runtime (JIT, GC, deopt). This task delivers *eliminated secret-dependent I/O branching + a tested amortized timing-variance bound across the must-be-indistinguishable DENY paths + retained network jitter (U-23) + a documented residual*, not mathematical constant-time.

**Files:**
- Modify: `src/packages/policy-engine/src/__tests__/anti-oracle.test.ts` (replace the placeholder test at line ~204)
- Modify (only if Step 3 shows the guard fails): `src/packages/policy-engine/src/engine.ts` (`result()` at line 694)
- Reference (do not modify): `src/packages/policy-engine/src/__tests__/engine-security-paths.test.ts` (reuse its `makeRequest` / `makePolicy` / `makeCredential` / `ctx` helpers as the pattern).

**Interfaces:**
- Consumes: `PolicyEngine.evaluate(request, context, credentials, policy): Promise<PolicyEvaluationResult>` (`engine.ts:165`); `result.reasonCodes: string[]`; `result.verdict: 'ALLOW' | 'PROMPT' | 'DENY'`.
- Produces: no new exported symbols. If mitigation is applied, `result()` gains an internal `await`ed timing floor for DENY verdicts only; its signature is unchanged.

- [ ] **Step 1: Document the return-point taxonomy in the register**

In `SECURE_1_FINDINGS_REGISTER.md`, add a "GAP-3 branching audit" subsection listing each `return this.result(...)` in `evaluate()` and classifying whether its call-depth correlates with a **holder secret** (user/credential existence, specific private deny reason) vs. a **verifier-controlled input** (unknown verifier, rate limit, malformed request). Only holder-secret-correlated depth differences are anti-oracle-relevant.

- [ ] **Step 2: Write the failing timing-variance guard (RED)**

Replace the placeholder test in `anti-oracle.test.ts` with a full-`evaluate()` amortized guard. Add at the top of the file (after existing imports):

```typescript
import { PolicyEngine, type EvaluationContext } from '../engine';
import { ProtectionLayer } from '@askmi/layer-resolver';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@askmi/shared-types';

const _cred = (o: Partial<StoredCredentialMetadata> = {}): StoredCredentialMetadata => ({
  id: 'cred-001', type: ['IDCredential'], issuer: 'did:example:gov',
  issuedAt: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 365 * 864e5).toISOString(),
  claims: ['age'], ...o,
});
const _policy = (o: Partial<PolicyManifest> = {}): PolicyManifest => ({
  version: '1.0.0',
  trustedIssuers: [{ did: 'did:example:gov', name: 'Gov', credentialTypes: ['IDCredential'] }],
  rules: [{
    id: 'r', verifierPattern: 'did:web:known.example',
    minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, allowedClaims: ['age'], provenClaims: [],
    requiresTrustedIssuer: true, maxCredentialAgeDays: 365, requiresUserConsent: false, priority: 10,
  }],
  globalSettings: { blockUnknownVerifiers: true }, ...o,
});
const _ctx = (): EvaluationContext => ({ timestamp: Date.now(), userDID: 'did:example:alice' });

async function meanEvalMs(
  engine: PolicyEngine, req: VerifierRequest, creds: StoredCredentialMetadata[], iters: number,
): Promise<number> {
  const policy = _policy();
  const start = performance.now();
  for (let i = 0; i < iters; i++) await engine.evaluate(req, _ctx(), creds, policy);
  return (performance.now() - start) / iters;
}
```

Then the guard test:

```typescript
describe('Anti-Oracle: end-to-end DENY timing variance (GAP-3)', () => {
  it('indistinguishable DENY paths have bounded mean-timing spread', async () => {
    const engine = new PolicyEngine();
    const ITERS = 500;

    // Path A: unknown verifier (early return, engine.ts:202)
    const unknownVerifier = { verifierId: 'did:web:stranger.example', requestedClaims: ['age'],
      requirements: [{ credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: [] }],
      nonce: 'n' } as VerifierRequest;

    // Path B: known verifier, claim not allowed (late return, engine.ts:273)
    const claimDenied = { verifierId: 'did:web:known.example', requestedClaims: ['ssn'],
      requirements: [{ credentialType: 'IDCredential', requestedClaims: ['ssn'], requestedProvenClaims: [] }],
      nonce: 'n' } as VerifierRequest;

    // Path C: known verifier, no suitable credential (holder-secret path)
    const noCredential = { verifierId: 'did:web:known.example', requestedClaims: ['age'],
      requirements: [{ credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: [] }],
      nonce: 'n' } as VerifierRequest;

    const a = await meanEvalMs(engine, unknownVerifier, [_cred()], ITERS);
    const b = await meanEvalMs(engine, claimDenied, [_cred()], ITERS);
    const c = await meanEvalMs(engine, noCredential, [], ITERS);

    const max = Math.max(a, b, c);
    const min = Math.min(a, b, c);
    // Amortized means, not single calls (single-call is GC/scheduler-dominated on CI).
    // Assert the SPREAD is bounded: no path leaks a holder secret via a large,
    // consistent latency gap. 2ms absolute spread tolerates JIT/GC noise while
    // still catching a pathological secret-dependent branch (e.g. an added I/O call).
    expect(max - min).toBeLessThan(2);
  });
});
```

- [ ] **Step 3: Run the guard — measure current behavior**

Run: `pnpm --filter @askmi/policy-engine exec vitest run src/__tests__/anti-oracle.test.ts -t "bounded mean-timing spread"`
Expected: one of two outcomes —
  - **PASS** → current code already keeps the spread bounded (all DENY work is in-memory sub-ms). The guard is a valid regression characterization test. Proceed to Step 5. Record in the register: "GAP-3: no secret-dependent I/O branch; spread already < 2ms; guard added."
  - **FAIL** → a real timing gap exists. Proceed to Step 4 (mitigation).

- [ ] **Step 4: (Only if Step 3 FAILED) Add a DENY-path timing floor in `result()`**

In `engine.ts`, inside `private async result(...)` (line 694), before returning a `DENY` verdict, pad to a fixed floor so all DENY outcomes share a minimum latency:

```typescript
// GAP-3: normalize DENY timing so verifiers cannot distinguish early vs. late
// denials via latency. Applies to DENY only — ALLOW/PROMPT latency is the user's
// own path and is not a cross-verifier oracle. Floor chosen > observed max spread.
if (verdict === 'DENY') {
  const DENY_FLOOR_MS = 5;
  const elapsed = Date.now() - startTime;
  if (elapsed < DENY_FLOOR_MS) {
    await new Promise((r) => setTimeout(r, DENY_FLOOR_MS - elapsed));
  }
}
```

Re-run the guard from Step 3. Expected: PASS. Confirm no other `policy-engine` test regressed on timing: `pnpm --filter @askmi/policy-engine test`.

- [ ] **Step 5: Verify the whole anti-oracle file + package are green**

Run: `pnpm --filter @askmi/policy-engine test`
Expected: PASS (all pre-existing anti-oracle assertions + the new guard).

- [ ] **Step 6: Commit**

```bash
git add src/packages/policy-engine/src/__tests__/anti-oracle.test.ts src/packages/policy-engine/src/engine.ts docs/qa/SECURE_1_FINDINGS_REGISTER.md
git commit -m "test(secure-1): GAP-3 anti-oracle timing-variance regression guard"
```

---

## Phase 3 — Fix findings (instantiated from Task 1)

**One task per `fix`-dispositioned row in the register.** Each follows the template below exactly. The worked example uses the *class* of the real 2026-07-13 GDPR false-success bug (unconditional `success: true` without a confirmed effect) so the shape is concrete; a real finding substitutes its own file/function/assertion. If a finding's fix would change a public package API, STOP and get approval before Step 3 (Global Constraints).

### Task F-«n»: Fix «finding-id» — «one-line description»

**Files:**
- Test: `«package»/src/__tests__/«area».test.ts`
- Modify: `«package»/src/«file».ts:«line»`

**Interfaces:**
- Consumes: the exact function under repair, by signature, as read in Task 1.
- Produces: unchanged public signature (fail-closed behavior change only). If the signature must change, this task is blocked pending approval.

- [ ] **Step 1: Write the failing regression test (RED)**

Write a test that reproduces the finding and asserts the fail-closed contract. Worked example (false-success class):

```typescript
it('reports failure (not success) when the signed request is never delivered', async () => {
  // Arrange: force the outward effect to fail (e.g. mock fetch → HTTP 500 / reject)
  vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: false, status: 500 } as Response);

  const result = await service.requestDataErasure(decisionId);

  // Fail-closed: no false success, and the audit reflects FAILED, not SENT.
  expect(result.success).toBe(false);
  expect(result.error).toBeTruthy();
  const events = await service.getAuditEvents();
  expect(events.find((e) => e.decision_id === decisionId)?.status).not.toBe('SENT');
});
```

- [ ] **Step 2: Run it — verify it FAILS for the right reason**

Run: `pnpm --filter «@askmi/package» exec vitest run src/__tests__/«area».test.ts -t "«test name»"`
Expected: FAIL because the current code returns `success: true` / writes `SENT` (the bug), NOT a typo/import error. If it errors instead of failing on the assertion, fix the test setup first.

- [ ] **Step 3: Apply the minimal fail-closed fix (GREEN)**

Change only what's needed to make the outcome fail-closed — e.g. gate `success` on a confirmed `res.ok`, propagate the error, write the audit status from the real result:

```typescript
const res = await this.postSignedRequest(endpoint, proofToken);
if (!res.ok) {
  await this.audit.append({ decision_id: decisionId, status: 'FAILED', http_status: res.status });
  return { success: false, error: `delivery_failed_${res.status}` };
}
await this.audit.append({ decision_id: decisionId, status: 'SENT', proof_token: proofToken });
return { success: true };
```

- [ ] **Step 4: Run the test — verify it PASSES + no regressions**

Run: `pnpm --filter «@askmi/package» test`
Expected: the new test passes and the package's existing tests stay green.

- [ ] **Step 5: Commit**

```bash
git add «package»/src/__tests__/«area».test.ts «package»/src/«file».ts docs/qa/SECURE_1_FINDINGS_REGISTER.md
git commit -m "fix(secure-1): «finding-id» — fail-closed «short description»"
```

Update the register row's disposition note to `fixed (commit <sha>)`.

---

## Phase 4 — Reconcile (docs; after all fixes are green)

### Task R-1: Correct GAP-2 and update GAP-3 in the threat model

**Files:**
- Modify: `docs/03-architecture/mvp/ADR-009_Threat_Model.md`

- [ ] **Step 1: Correct GAP-2 (recovery is implemented)**

In the Gap-Analyse table and the Device-Loss scenario's Residualrisiko, change GAP-2 from "Recovery bei Device-Loss nicht implementiert" to a closed/residual entry citing the real implementation: `shared-crypto/src/recovery.ts` (Shamir Secret Sharing 2-of-3 over GF(2⁸), "Trust Circle" social recovery), wired in `WalletService.ts` + `App.tsx`, QA evidence `docs/qa/WALLET_RECOVERY_RC_2026-06-04.md`. State the residual honestly (e.g. no remote-wipe; guardian trust assumptions).

- [ ] **Step 2: Update GAP-3 to mitigated + residual**

Change GAP-3's status from open to "mitigated — bounded timing-variance guard + retained U-23 jitter; residual: no mathematical constant-time in V8." Cite the new test `anti-oracle.test.ts → "indistinguishable DENY paths have bounded mean-timing spread"` and, if applied, the `result()` DENY floor.

- [ ] **Step 3: Add STRIDE rows for swept-and-fixed findings + update change log**

For each Phase-3 `fix`, add or update the matching STRIDE row (Evidenz-Status "belegt" + the new test reference). Append a Change Log entry dated 2026-07-13 summarizing SECURE-1. Update the Fail-Closed Acceptance table if GAP counts changed.

- [ ] **Step 4: Commit**

```bash
git add docs/03-architecture/mvp/ADR-009_Threat_Model.md
git commit -m "docs(secure-1): reconcile ADR-009 threat model to true state (GAP-2 closed, GAP-3 mitigated)"
```

### Task R-2: Align BACKLOG + STATE

**Files:**
- Modify: `docs/BACKLOG.md` (S-10 row + a 2026-07-13 SECURE-1 update note)
- Modify: `STATE.md` (Recent additions + security-posture line)

- [ ] **Step 1: Update S-10 and add a SECURE-1 note in BACKLOG.md**

Note the sweep closure and GAP-2/GAP-3 reconciliation; keep GAP-4 (external review) honestly open. Follow the existing dated-update-note style at the top of `BACKLOG.md`.

- [ ] **Step 2: Add a Recent-additions entry in STATE.md**

One entry dated 2026-07-13 summarizing SECURE-1 with validation results (test/lint/guard counts).

- [ ] **Step 3: Commit**

```bash
git add docs/BACKLOG.md STATE.md
git commit -m "docs(secure-1): align BACKLOG + STATE with gap closure"
```

### Task R-3: Write the dated QA evidence record

**Files:**
- Create: `docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md`
- Modify: `docs/qa/README.md` (add the index line, per H-10 convention)

- [ ] **Step 1: Write the evidence record**

Include: the full findings register (final, all dispositioned), per-fix test references + commit shas, the GAP-3 branching-audit taxonomy + guard result + the verbatim honesty boundary, and the final validation block (Step 2 results). Add the index line to `docs/qa/README.md`.

- [ ] **Step 2: Run the full validation block and paste results into the record**

Run: `pnpm test` then `pnpm lint` then `pnpm guard:rebrand`
Expected: 46/46 turbo tasks green; lint 0/0; guard green. Paste the summary lines into the record.

- [ ] **Step 3: Commit**

```bash
git add docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md docs/qa/README.md
git commit -m "docs(secure-1): QA evidence record for gap closure + bug sweep"
```

### Task R-4: Final green-bar verification + PR

- [ ] **Step 1: Full suite + lint + guard, one last time**

Run: `pnpm test && pnpm lint && pnpm guard:rebrand`
Expected: all green. If anything is red, it is a Phase-3/Phase-2 regression — fix before proceeding.

- [ ] **Step 2: Push the branch and open a PR**

```bash
git push -u origin feat/secure-1-gap-closure
gh pr create --title "SECURE-1: security gap closure + fail-closed bug sweep" --body "Closes code-fixable security gaps on the wallet + policy + crypto surface (TDD), adds the GAP-3 anti-oracle timing-variance guard, and reconciles ADR-009 (GAP-2 recovery already implemented; GAP-3 mitigated). GAP-1 (TEE) and GAP-4 (external review) remain honestly open. Evidence: docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md"
```

---

## Self-Review (completed by author)

**1. Spec coverage:**
- Spec §4 Part C (Sweep) → Task 1. ✓
- Spec §4 Part B (GAP-3) → Task 2. ✓
- Spec §4 Part A (Reconcile) → Tasks R-1..R-3. ✓
- Spec §5 (TDD) → Global Constraints + every Phase-3 task. ✓
- Spec §6 (fail-closed) → Global Constraints + Task 2 mitigation + F-template Step 3. ✓
- Spec §7 (Definition of Done) → Task R-4 green bar + R-3 evidence + register completeness. ✓
- Spec §8 risk "public API change" → Global Constraints + F-template guard. ✓
- Spec §9 (SECURE-2 successor) → out of scope, not planned here. ✓

**2. Placeholder scan:** The `«...»` tokens in the Phase-3 *template* are intentional instantiation slots, explicitly filled per-finding from Task 1's register — not TBDs in a fixed task. GAP-3's Step 4 is conditional on a measured RED, with complete code provided for both branches. No "add error handling"-style vagueness remains.

**3. Type consistency:** `evaluate(request, context, credentials, policy): Promise<PolicyEvaluationResult>` and `result()` (private async, unchanged signature) are used consistently. Test helper names (`_cred`/`_policy`/`_ctx`/`meanEvalMs`) are locally defined in Task 2's code. `PolicyEngine`, `ProtectionLayer`, `EvaluationContext`, `VerifierRequest`, `StoredCredentialMetadata`, `PolicyManifest` match their real import sources verified in the codebase.
