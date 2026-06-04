# Big Audit Slice — Constants & Contracts

**Date:** 2026-06-04
**Scope:** first Sprint 02 implementation slice after AskMI rebrand
**Branch:** `chore/full-askmi-rebrand`

## What Changed

- Added `src/packages/shared-types/src/askmi.ts` as the shared home for
  runtime/demo identifiers:
  - demo issuer URI/base URL/status-list URL/trust-list URL
  - demo verifier DID and wallet audience
  - AskMI env var names with documented legacy MITCH fallbacks
  - wallet/WebAuthn storage keys
  - scenario IDs and scenario VCT URIs
- Replaced duplicated literals in active flow code:
  - verifier backend OID4VP request, DID document, trust/status fixtures
  - OID4VP demo VCT map
  - wallet OID4VP flow
  - wallet-core policy storage
  - shared-crypto WebAuthn storage/session keys
  - phase0 direct verifier DID
  - verifier frontend wallet deep link
- Fixed one active stale rebrand bug:
  - verifier frontend QR/deep link still encoded `did:mitch:verifier-liquor-store`.
- Fixed one active CI config drift:
  - layer-validation workflow still filtered `@mitch/policy-engine`.
## Audit Findings

### High Payoff, Fixed

- Demo identity constants were repeated across backend, wallet, protocol tests,
  and frontend QR generation. Centralizing them prevents verifier DID / issuer
  / status-list drift from silently breaking the pilot flow.
- WebAuthn and wallet policy storage keys were locally duplicated. Centralizing
  them reduces migration risk if storage names ever need versioning.
- `SCENARIO_VCT` belonged to the protocol flow but encoded product-level demo
  contracts. It now delegates to the shared AskMI constants while preserving
  the existing OID4VP export.

### Still Intentional / Deferred

- Many tests still contain literal demo DIDs. Those are acceptable where the
  literal is the assertion subject. Convert only shared setup fixtures or tests
  that mirror runtime constants.
- Historical docs/archive still contain `did:mitch`, `mitch.demo`, and
  `@mitch/*` references. They should stay unless a docs migration is explicitly
  scoped; dated evidence should preserve what happened at that time.
- Frontend scenario copy and wallet credential display data still duplicate
  scenario names/claims. A dedicated demo-fixtures module is likely useful, but
  it should be a separate slice because it affects UX copy and test expectations.

## Verification

- `pnpm --filter @askmi/shared-types build` — pass
- `pnpm --filter @askmi/oid4vp test` — pass, 86 tests
- `pnpm --filter verifier-backend test` — pass, 88 tests
- `pnpm --filter @askmi/shared-crypto build` — pass
- `pnpm --filter @askmi/wallet-core build` — pass
- `pnpm --filter @askmi/phase0-security test` — pass, 149 tests
- `pnpm --filter verifier-frontend build` — pass
- `pnpm --filter @askmi/wallet-pwa test -- App.test.tsx` — pass, 7 tests
- `pnpm test` — pass, 45/45 Turbo tasks
- `pnpm build` — pass, 30/30 Turbo tasks
- `pnpm lint` — pass, 10/10 Turbo tasks
- Active-code rebrand scan — pass:
  `rg "did:mitch|mitch\.demo|@mitch/|MitchPolicyEvaluator" src .github package.json pnpm-workspace.yaml turbo.json`

Note: `pnpm --filter @askmi/shared-crypto test -- webauthn` was attempted first
but Vitest found no matching `webauthn` test file. The package build and full
root test run passed afterwards.

## Follow-Up Backlog

- Extract scenario fixture data only if we can preserve the frontend narrative
  without turning UX copy into a generic data dump.
- Add a small active-code rebrand guard in CI, scoped to `src`, `.github`,
  `package.json`, `pnpm-workspace.yaml`, and `turbo.json`, excluding archive and
  historical docs.
- Consider moving trust-list/status-list test fixture builders into a reusable
  test helper once a second runtime test needs the same fixture shape.
