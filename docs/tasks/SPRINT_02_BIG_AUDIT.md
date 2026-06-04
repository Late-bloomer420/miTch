# Sprint 02 — Big Audit After AskMI Rebrand

**Date:** 2026-06-04
**Status:** in progress
**Depends on:** Full AskMI rebrand PR merged

## Goal

Audit the whole repository after the full AskMI rebrand with two priorities:

1. Verify that security/privacy behavior did not regress.
2. Identify where the repo duplicates logic instead of using reusable modules,
   constants, contracts, fixtures, and test helpers.

## Audit Tracks

### A. Rebrand Consistency

- Active code/config has no stale `@mitch/*`, `mitch.demo`, or `did:mitch`
  identifiers.
- Historical docs may retain old names only when they clearly describe old
  evidence or migration history.
- Runtime compatibility fallbacks are intentional and documented.

### B. Reusable Code & Duplication

- Find repeated constants: app audience IDs, demo DIDs, issuer URLs, VCT URIs,
  localStorage/sessionStorage keys, env var names, scenario IDs.
- Find repeated flow code: OID4VP request building, SD-JWT presentation setup,
  trust-list/status-list test fixtures, policy evaluation wrappers.
- Promote repeated logic into shared modules only where it reduces real risk or
  removes meaningful maintenance burden.

### C. Security & Privacy Invariants

- Recheck fail-closed paths: trust source unavailable, status source unavailable,
  revoked credentials, audience mismatch, replay, verifier spoofing.
- Recheck no-PII logging expectations in verifier/backend/wallet flows.
- Recheck unlinkability and pairwise DID assumptions after identifier changes.

### D. Tests & CI Shape

- Ensure source tests do not accidentally include stale `dist/` output.
- Verify package builds are deterministic after clean checkout.
- Confirm smoke matrix remains CI-ready and does not rely on manual evidence.

## First Commands

```powershell
rg '@mitch/|mitch\.demo|did:mitch|MitchPolicyEvaluator' -S . --glob '!**/node_modules/**' --glob '!**/dist/**'
pnpm -r build
pnpm test
pnpm lint
```

## Expected Deliverables

- Audit report under `docs/qa/`.
- Refactoring backlog entries grouped by risk and payoff.
- Small follow-up PRs for confirmed high-value reuse or security fixes.

## Progress

- 2026-06-04: Completed first constants/contracts slice. See
  `docs/qa/BIG_AUDIT_CONSTANTS_CONTRACTS_2026-06-04.md`.
- 2026-06-04: Completed wallet policy storage hardening follow-up. The wallet
  now stores the policy manifest in `SecureStorage`, migrates the legacy
  `localStorage` value once, removes it, and hides the system policy document
  from the credential list.
- 2026-06-04: Added active-code rebrand guard to CI. `pnpm guard:rebrand`
  scans `src`, `.github`, and root config files for stale `@mitch/*`,
  `did:mitch`, `mitch.demo`, and `MitchPolicyEvaluator` references while
  leaving historical docs/evidence out of scope.
