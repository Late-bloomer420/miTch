# SECURE-1 Gap Closure — QA Evidence Record

**Date:** 2026-07-13
**Branch:** `feat/secure-1-gap-closure`
**Controller-verified:** 2026-07-13
**Result:** PASS

---

## Scope

Sprint SECURE-1 targeted fail-closed security hardening: a systematic sweep of
`WalletService`, `policy-engine`, `shared-crypto`, and `oid4vp-verifier` for
fail-open paths, false-success stubs, swallowed errors, and contract mismatches,
followed by real credential signature verification (F-14) and an anti-oracle
timing-variance regression guard (GAP-3).

---

## SECURE-1 Delivery Summary

| ID | Fix | Commit |
|----|-----|--------|
| F-01 | `getIdentityPublicKey()` read wrong field (`publicKey`) → reads `auditPublicKey` | 14ab393 |
| F-02 | `savePolicy()` fire-and-forget → async, persist-before-mutate, surfaces failure | 6fb7e08 |
| F-03 | `WebAuthnService.verifyPresence()` false-success stub → tombstoned, throws fail-closed (`@deprecated`, zero callers) | dc0bdca |
| F-04 | `isAllowedByGeoScope()` double fail-open (undetermined country / unknown scope → `true`) → fail-closed DENY | 8bf997e |
| F-16 + F-18 | `savePasskeyMeta` / `saveIdentityKeyMeta` swallowed IndexedDB errors in empty catch → fail-closed rethrow | fb764bb |
| F-14 | `oid4vp-verifier` did NO credential signature verification → real SD-JWT VC issuer-sig + KB-JWT verification via `@askmi/shared-crypto`, opt-in, fail-closed, `signaturesVerified` field | 74d2e12 (dep) + 703f06d |
| GAP-3 | Anti-oracle timing-variance regression guard (interleaved + warm-up, 500 iterations each path); NO secret-dependent I/O branch found → no engine mitigation applied | 7643a59 + c71ded7 |

---

## Full Findings Register Outcome

Source of truth: [`SECURE_1_FINDINGS_REGISTER.md`](SECURE_1_FINDINGS_REGISTER.md)

22 findings dispositioned:

| Disposition | Count | Finding IDs |
|---|---|---|
| `fix` (code corrected, TDD) | 7 | F-01, F-02, F-03, F-04, F-14, F-16, F-18 |
| `documented-residual` (acknowledged, out-of-scope or by design) | 7 | F-05, F-06, F-15, F-19, F-20, F-22, GAP-3 partial |
| `not-a-bug` (rationale confirmed) | 9 | F-07, F-08, F-09, F-10, F-11, F-12, F-13, F-17, F-21 |

**Documented-residual rationale (summary):**
- F-05/F-06: L2-anchor client is a documented stub (on-chain deployment out of scope).
- F-15: Break-glass is a required EHDS Art. 8(5) feature with mandatory audit trail.
- F-19: Best-effort audit-log persistence is the documented design intent.
- F-20: Pairwise-DID failure is non-blocking by design; fixing requires a separate pairwise-DID task.
- F-22: Batch-timer `processBatch` fire-and-forget is acceptable until real L2 integration.

---

## Per-Fix Commit and Test References

### F-01 — `getIdentityPublicKey()` wrong field (commit 14ab393)
`WalletService.ts:1640` cast `AuditLog` to `{ publicKey? }` but field is `auditPublicKey`.
Always returned `null`, breaking the GDPR-erasure signing path.
**Tests:** `wallet-pwa/src/__tests__/WalletService.test.ts` — F-01 key-field regression test.

### F-02 — `savePolicy()` fire-and-forget (commit 6fb7e08)
`savePolicy()` called `persistPolicy()` with `void …catch(console.error)`.
Policy write failures were logged but callers received no signal; in-memory state
could diverge from persistent state silently.
**Tests:** `wallet-pwa/src/__tests__/WalletService.test.ts` — F-02 persist-before-mutate test.

### F-03 — `WebAuthnService.verifyPresence()` false-success stub (commit dc0bdca)
`verifyPresence()` returned `true` for any non-empty attestation string without
cryptographic verification. Zero call sites; risk was latent, not live.
Tombstoned: now throws fail-closed.
**Tests:** `src/packages/shared-crypto/test/webauthn-fail-closed.test.ts` — F-03 fail-closed on verifyPresence.

### F-04 — `isAllowedByGeoScope()` double fail-open (commit 8bf997e)
Line 17: returned `true` when country was undetermined ("fail-open for geo only").
Line 22: returned `true` as default for unrecognised `geoScope` value.
Both violate the fail-closed invariant; both corrected to DENY.
**Tests:** `src/packages/policy-engine/src/__tests__/ehds-geo-scope.test.ts` — F-04 fail-closed paths.

### F-16 + F-18 — IndexedDB error swallow (commit fb764bb)
`savePasskeyMeta()` and `saveIdentityKeyMeta()` had empty `catch` blocks ("will be ignored").
Failed saves caused `isIdentityRegistered()` to return `false` on next load, silently
downgrading the security level.
**Tests:** `src/packages/shared-crypto/test/webauthn-save-failclosed.test.ts` — F-16/F-18 rethrow tests.

### F-14 — Real credential signature verification (commits 74d2e12 + 703f06d)
`verifyAuthorizationResponse()` previously checked only structural submission constraints.
`valid: true` meant structural compliance only, not cryptographic authenticity.
Now: `validateSDJWTVC` + `validateKeyBindingJWT` from `@askmi/shared-crypto` wired in.
New options: `verifyCredentialSignatures`, `resolveIssuerKey`, `expectedAudience`.
New result field: `signaturesVerified`.
Fail-closed on missing resolver, null/wrong key, KB-JWT mismatch, or unknown format.
Opt-in; existing structural-only callers remain backward-compatible.
**Tests:** `src/packages/oid4vp-verifier/src/__tests__/response-verifier.crypto.test.ts` — 7 new TDD crypto tests (RED→GREEN);
60 total tests pass; build clean.
Package counts during sprint: oid4vp-verifier 60.

---

## GAP-3 Branching Taxonomy Summary

**Audit scope:** every `return this.result(...)` call in `evaluate()` (`engine.ts:165`)
classified by whether its call depth correlates with a **holder secret** vs. a
**verifier-controlled input**.

Only holder-secret-correlated depth differences are anti-oracle-relevant.

| Path | Reason Code | Secret Class | Anti-Oracle Relevant? |
|------|-------------|--------------|----------------------|
| Line 202 | `UNKNOWN_VERIFIER` | verifier-controlled | No |
| Line 204 | `NO_MATCHING_RULE` | verifier-controlled | No |
| Line 215 | `RATE_LIMIT_EXCEEDED` | verifier-controlled | No |
| Line 239 | `AGENT_NOT_AUTHORIZED` / delegation | verifier-controlled | No |
| Line 246 | purpose-binding codes | verifier-controlled | No |
| Line 267 | `CLAIM_NOT_ALLOWED` (explicit deny) | verifier-controlled | No |
| Line 273 | `CLAIM_NOT_ALLOWED` (empty intersection) | verifier-controlled | No |
| **Line 312** | **`NO_SUITABLE_CREDENTIAL` / EXPIRED** | **HOLDER SECRET** | **YES** |
| Line 343 | `SECONDARY_USE_DENIED` | verifier-controlled | No |
| Line 351 | `GEO_SCOPE_VIOLATION` | verifier-controlled | No |
| Line 362 | `HDAB_PERMIT_REQUIRED` | verifier-controlled | No |
| Line 370 | `GEO_SCOPE_VIOLATION` (matchedRule) | verifier-controlled | No |
| Line 404 | sanity/conflict codes | verifier-controlled | No |

**Finding:** Only line 312 (`NO_SUITABLE_CREDENTIAL` family) is holder-secret-correlated —
its execution traverses the full credential scan (`selectCompatibleCredentialsForRequirement`),
whereas early DENY paths skip it. All work is in-memory, sub-millisecond; no I/O branches.

**Must-be-indistinguishable paths for the guard:**
- Path A: `UNKNOWN_VERIFIER` (line 202) — early, no credential scan
- Path B: `CLAIM_NOT_ALLOWED` (line 273) — mid, no credential scan
- Path C: `NO_SUITABLE_CREDENTIAL` (line 312) — late, full credential scan (empty input)

**Guard result:** amortised mean spread < 2 ms across 500 iterations each path.
Guard passes on current code.
Test: `anti-oracle.test.ts → "indistinguishable DENY paths have bounded mean-timing spread"`.

**Honesty boundary (verbatim):** True constant-time execution is unattainable in a browser
JS/V8 runtime (JIT, GC, deopt). This task delivers *eliminated secret-dependent I/O
branching + a tested amortised timing-variance bound across the must-be-indistinguishable
DENY paths + retained network jitter (U-23) + a documented residual*, not mathematical
constant-time.

---

## GAP-2 Reconciliation

**Previous ADR-009 entry (stale):** "Recovery bei Device-Loss nicht implementiert
(kein Remote-Wipe, kein Guardian)."

**Corrected state:** `src/packages/shared-crypto/src/recovery.ts` implements real
Shamir Secret Sharing (2-of-3 over GF(2⁸)) as "Trust Circle" social recovery.
Wired into `WalletService.ts` and `App.tsx`.
QA evidence: [`WALLET_RECOVERY_RC_2026-06-04.md`](WALLET_RECOVERY_RC_2026-06-04.md).

**Reclassification:** GAP-2 → **closed with residual**.
Residual: no remote-wipe (TEE precondition, see GAP-1 / ADR-010 deferred);
guardian-trust assumptions (social recovery model requires trusted contacts).

ADR-009 updated accordingly (Change Log entry 2026-07-13).

---

## Verified Final Validation

Verified by the controller on 2026-07-13. Do not re-derive these numbers from the
test output — they are the authoritative, point-in-time evidence for this sprint.

| Check | Result |
|---|---|
| `pnpm test` | **46/46 turbo tasks green** |
| `pnpm lint` | **0 errors, 7 warnings** — all 7 are pre-existing `@typescript-eslint/no-explicit-any` in `wallet-pwa`, present since the SECURE-1 baseline (Task 0); count unchanged 7→7; SECURE-1 introduced **zero new warnings** |
| `pnpm guard:rebrand` | **passed** |
| Per-package (sprint) | policy-engine 325 tests, shared-crypto 273 tests, wallet-pwa 185 tests, oid4vp-verifier 60 tests |

---

## Gap Status After SECURE-1

| GAP | Status | Notes |
|-----|--------|-------|
| GAP-1 (browser RAM not physically wipeable) | 🟡 **Open** | Requires TEE (ADR-010, deferred); no fix possible in browser JS |
| GAP-2 (recovery at device loss) | 🟢 **Closed with residual** | Shamir SSS implemented; residual: no remote-wipe, guardian-trust assumptions |
| GAP-3 (timing side-channel at anti-oracle) | 🟡 **Mitigated, documented residual** | Bounded-variance guard + jitter retained; true constant-time unattainable in V8 |
| GAP-4 (external security review) | 🔴 **Open** | Human precondition for full `Accepted`; preparation is SECURE-2 |
