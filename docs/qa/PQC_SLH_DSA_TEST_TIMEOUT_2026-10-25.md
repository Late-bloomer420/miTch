# SLH-DSA test-timeout flake fix — 2026-10-25

Scope: `@askmi/shared-crypto` `test/pqc.test.ts` only (SLH-DSA-SHA2-128s
describe block). No crypto implementation change; no policy or protocol change.
Branch `fix/pqc-slh-dsa-test-timeout`, base master `5e25221`, Node v24.16.0,
pnpm 9.15.9, Windows.

## Observed history (three dated instances)

1. **2026-07-12** — `docs/qa/WEBAUTHN_FAIL_CLOSED_2026-07-12.md` records
   `pqc.test.ts` SLH-DSA as a "pre-existing, unrelated timing failure" that
   also fails on clean master.
2. **2026-10-25, Actions run 40197696547** (PR #211 cycle) —
   `SLH-DSA-SHA2-128s > round-trip sign/verify` **"Test timed out in 30000ms"**
   (package testTimeout). Same run passed on re-run of the failed job.
3. **2026-10-25T12:53Z ci.yml failure** on PR #213's head — same PQC-suite
   timeout signature.

## Root cause

SLH-DSA-SHA2-128s keygen+sign is inherently expensive — measured **≈7s per
keygen+sign locally on an idle machine** (the slow "128s" variant is the
security property, not a defect). The two tests each performed a full
keygen+sign (~14s CPU), and under the shared-crypto suite's 30+ parallel test
files on small CI runners, CPU contention multiplies wall time past the 30s
package `--testTimeout`. Running the file directly (`npx vitest run`, without
the package script flag) uses the 5s default and both SLH-DSA tests always
failed — a separate footgun.

## Fix

Master (parallel session, 2026-10-25) already carried a describe-level
`{ timeout: 120_000 }` for the SLH-DSA block. This change **adds on top**:

- Hoist `keygen`+`sign` into one `beforeAll` fixture shared by both tests
  (halves the expensive work; assertions unchanged).
- The beforeAll hook keeps an explicit 120s budget; the describe-level timeout
  from master covers the tests.
- Assertions and semantics preserved: valid signature verifies; tampered
  first byte fails verification.

## Verification (local, 2026-10-25)

- `npx vitest run test/pqc.test.ts` (5s default budgets): **25/25 passed** —
  the direct-run footgun is gone.
- `pnpm --filter @askmi/shared-crypto test`: **32/32 files, 312/312 tests**
  (includes the dist-compiled and webauthn-identity suites), with the SLH-DSA
  file no longer at risk of contention timeouts.

This is a test-infrastructure fix, not a security PASS or a crypto-claim
change. CI on the PR head is the next evidence.
