# Sprint 1A — Pilot Flow Rerun

**Status:** in progress  
**Started:** 2026-06-04  
**Branch:** `qa/pilot-flow-rerun-2026-06-04`

## Goal

Make the local pilot flow a hard, repeatable truth source after Sprint 0.

The current repository has strong documentation claims and many completed
technical layers, but the live demo surface must be re-verified from the actual
runtime: issuer mock, verifier backend, wallet PWA, trust list, revocation list,
and the five scenario matrix.

## Scope

- Re-run the local pilot flow on ports `3005` issuer, `3004` verifier, and
  `5174` wallet.
- Verify the five demo scenarios:
  - `liquor-store`
  - `doctor-login`
  - `ehds-er`
  - `pharmacy`
  - `revoked`
- Fix only fixture/runtime drift required to make the existing demo truthful.
- Record findings under `docs/qa/`.
- Keep broader product work out of this sprint.

## Findings So Far

1. **Trust-list fixture drift**
   - The runtime issuer used by the OID4VP demo is `https://issuer.askmi.demo`.
   - The local EUDI LOTL fixture trusted `did:web:localhost%3A3005` and
     `did:web:issuer.askmi.demo`, but not the runtime HTTPS issuer URI.
   - Result before fix: every `/wallet-present` scenario failed with
     `ENTITY_NOT_IN_TSL: https://issuer.askmi.demo`.

2. **Revocation fixture drift**
   - The revoked demo credential embedded `https://example.com/status-list/1`.
   - The local verifier cannot rely on that external placeholder in an offline
     pilot rerun.
   - Result before fix: revoked scenario failed closed, but with
     `STATUS_SOURCE_UNAVAILABLE` instead of a real revocation decision.

3. **Generated `dist/` can become stale**
   - After the npm scope rename, some tests still consumed old build output until
     affected packages were rebuilt.
   - Operational rule: rebuild local package `dist/` before treating verifier
     backend test results as authoritative.

## Current Acceptance Target

- Positive scenarios return HTTP 200 and disclose only the expected claims.
- `revoked` returns HTTP 403 with `REVOKED`.
- Targeted tests pass for the touched runtime packages.
- QA evidence file captures commands/results without committing local log output.

## Non-Scope

- No UI redesign.
- No broad rebrand work.
- No CI expansion yet.
- No production trust-list architecture changes beyond local demo fixture
  alignment.
