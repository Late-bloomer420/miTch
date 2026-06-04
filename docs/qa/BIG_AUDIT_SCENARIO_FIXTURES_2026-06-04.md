# Big Audit Slice — Demo-Scenario Fixtures (S2-04)

**Date:** 2026-06-04
**Scope:** Sprint 02 slice S2-04 — demo-scenario claim fixtures
**Branch:** `chore/s2-04-scenario-fixtures` (off `chore/full-askmi-rebrand`)

## What Changed

- Added `ASKMI_SCENARIO_CLAIMS` to `src/packages/shared-types/src/askmi.ts` as the
  single source of truth for per-scenario demo claim values.
- `src/apps/wallet-pwa/src/scenario-claims.ts` now re-exports the canonical object
  (drops its private copy).
- `src/apps/verifier-demo/backend/src/app.ts` now derives its `SCENARIO_CLAIMS`
  from the canonical object, aliasing the holder-domain key `birthDate` to the
  protocol key `dateOfBirth` at that boundary.
- `src/apps/verifier-demo/frontend/src/data/scenarios.ts` kept as local
  presentation copy; only the drifted `doctor-login` age value was corrected
  (24 → 35) plus its cosmetic `birthDate` for internal consistency.

## Audit Findings

### Drift, Fixed

- The same demo claims were **triplicated** (wallet PWA, verifier-demo backend,
  verifier frontend) and had already drifted: `doctor-login.age` was **24** in the
  frontend but **35** in both the backend (the functional OID4VP disclosure
  source) and the wallet. Unified on **35** — the backend is the live disclosure
  path, the wallet agrees, and 35 is plausible for a surgeon. The frontend's 24
  was the stale display copy.

### Intentional Layering, Preserved (NOT unified)

- The backend/protocol layer uses the claim key `dateOfBirth`; the wallet/holder
  domain uses `birthDate`. `WalletService` already aliases `birthDate ->
  dateOfBirth` at the protocol boundary, and backend tests
  (`oid4vp-present`, `wallet-present.smoke`, `present.headers.int`) plus the
  issuer-mock assert on `dateOfBirth`. The canonical fixtures use the
  holder-domain `birthDate`; the backend re-applies the alias. Unifying the key
  names would have destroyed a correct layer boundary.

### Intentional UX Copy, Deferred

- The verifier frontend `data/scenarios.ts` is a presentation mockup with
  display-only strings (e.g. `salary: '€ [redacted]'`, `'[redacted]'`,
  emoji/label/verdict/`isProof`/`blocked`). Per the S2-04 acceptance criterion
  ("reuse claims/scenario IDs without unnecessarily generalizing UX copy"), its
  structure was left local and not forced to derive from the canonical object.
  Only the drifted age value was corrected.

## Verification

- `pnpm --filter @askmi/shared-types build` — pass
- `pnpm build` — pass, 30/30 Turbo tasks
- `pnpm test` — pass, 45/45 Turbo tasks (wallet-pwa 94, verifier-backend green)
- `pnpm lint` — pass, 10/10 Turbo tasks
- `pnpm guard:rebrand` — pass

## Follow-Up Backlog

- Optional: add a small drift-guard test asserting the frontend's non-redacted
  display values stay consistent with `ASKMI_SCENARIO_CLAIMS`, so the
  deliberately-decoupled presentation copy cannot silently drift again.
- S2-05 (P2) remains open: promote trust-/status-list test fixtures into a
  reusable test helper.
