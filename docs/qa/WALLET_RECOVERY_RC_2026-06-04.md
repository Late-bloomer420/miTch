# Wallet Recovery RC QA Evidence

**Date:** 2026-06-04
**Branch:** `master`
**Commit:** `f2a6ae1` (`fix(wallet): verify age predicate proof flow`)
**Tag:** `v1.0.1-wallet-recovery-rc`
**Result:** PASS

## Scope

This run validates the recovered wallet baseline after the Phase 6 rollback and the age
predicate proof regression fix. The canonical local demo target is:

| Service | Canonical port |
|---|---:|
| Wallet PWA | 5174 |
| Verifier backend | 3004 |
| Issuer mock | 3005 |

Port `5175` is not a release target. It may appear only when Vite falls back because an
older wallet dev server is still occupying `5174`.

## Local Flow Acceptance

The wallet was tested in the browser against `http://localhost:5174/?demo=wallet` with
the verifier backend on `3004` and issuer mock on `3005`.

| Check | Result | Notes |
|---|---|---|
| Wallet seed render | PASS | 6 credential cards rendered from the recovered wallet state |
| OID4VCI issuance | PASS | Test credential fetched from issuer mock; wallet card count increased to 7 |
| Age proof | PASS | `/present` returned `200`; verifier accepted the signed predicate proof |
| Doctor login | PASS | Policy prompt shown and presentation completed |
| EHDS emergency access | PASS | Policy prompt shown with biometric step-up required |
| Pharmacy prescription | PASS | Policy prompt shown and presentation completed |
| Browser console/page errors | PASS | No blocking runtime errors during the accepted flow |

## Regression Fixed

The age proof flow had two hard failures before this RC:

- The wallet predicate evaluator expected `credentialSubject.dateOfBirth`, while recovered
  demo credentials used `birthDate` / `birth_date`. The wallet now maps these aliases in
  memory before predicate evaluation.
- The wallet generated predicate proofs with the wrong key context for verifier-side
  validation. Predicate proof signatures are now produced with the ephemeral proof key and
  include the matching public JWK in the proof payload.

The verifier backend was also aligned with the current predicate result shape:
`zkpProof.proof.binding.nonce` and `zkpProof.proof.evaluatedAt`.

## Test Gates

Local gates completed before the commit:

| Gate | Result |
|---|---|
| `pnpm --filter @askmi/wallet-pwa test` | PASS, 92 tests |
| `pnpm --filter verifier-backend test` | PASS, 78 tests |
| `pnpm build` | PASS, 30/30 tasks |
| `pnpm test` | PASS, 45/45 tasks |
| `pnpm lint` | PASS, existing non-blocking verifier frontend `any` warning only |
| `pnpm audit` | PASS, no known vulnerabilities |
| `git diff --check` | PASS |

GitHub Actions on `master` after push:

| Workflow | Run | Result |
|---|---:|---|
| miTch CI/CD Pipeline | `26925568127` | PASS |
| ci-security | `26925568092` | PASS |
| CodeQL | `26925567685` | PASS |
| Deploy GitHub Pages | `26925568128` | PASS |

GitHub emitted a Node.js 20 Actions deprecation annotation for the workflow actions.
That is not a wallet regression, but should be handled in CI maintenance before GitHub's
Node 20 removal window.
