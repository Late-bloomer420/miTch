# Pilot Flow Rerun — 2026-06-04

**Branch:** `qa/pilot-flow-rerun-2026-06-04`  
**Purpose:** Sprint 1A evidence for the local issuer/verifier/wallet pilot flow.

## Runtime

Local services:

- Issuer mock: `http://localhost:3005`
- Verifier backend: `http://localhost:3004`
- Wallet PWA: `http://localhost:5174/?demo=wallet`

Health checks:

- `GET http://localhost:3005/health` -> `ok`, keys ready
- `GET http://localhost:3004/health` -> `ok`
- `GET http://localhost:5174/?demo=wallet` -> HTTP 200
- `GET http://localhost:3005/status-list/1` -> StatusList2021 fixture present

## Fixes Applied

### Trust-list Fixture

The local EUDI LOTL fixture now includes the runtime issuer URI used by the demo:

- `https://issuer.askmi.demo`

Before this fix, all five `/wallet-present` scenarios failed with:

```text
ENTITY_NOT_IN_TSL: https://issuer.askmi.demo
```

### Revocation Fixture

The issuer mock now serves a local StatusList2021 credential at:

```text
http://localhost:3005/status-list/1
```

The demo presentation builder accepts an optional `statusListUri`, and the local
verifier/wallet use the issuer mock URL for the revoked scenario.

Direct resolver check:

```json
{
  "decision": "DENY",
  "revoked": true,
  "reason": "REVOKED",
  "denyCode": "DENY_CREDENTIAL_REVOKED",
  "listUrl": "http://localhost:3005/status-list/1",
  "fromCache": false,
  "graceMode": false
}
```

## Live Scenario Matrix

| Scenario | HTTP | Result | Disclosed claims / error |
|---|---:|---|---|
| `liquor-store` | 200 | ok | `age` |
| `doctor-login` | 200 | ok | `age`, `role`, `licenseId` |
| `ehds-er` | 200 | ok | `bloodGroup`, `allergies`, `emergencyContacts` |
| `pharmacy` | 200 | ok | `medication`, `dosageInstruction`, `refillsRemaining` |
| `revoked` | 403 | denied | `REVOKED` |

## Targeted Verification

Passed locally:

- `pnpm --filter @askmi/oid4vp test` -> 86 tests
- `pnpm --filter @askmi/issuer-mock test` -> no tests, pass-with-no-tests
- `pnpm --filter @askmi/wallet-pwa test` -> 92 tests
- `pnpm --filter verifier-backend test` -> 78 tests
- `pnpm --filter @askmi/oid4vp build`
- `pnpm --filter @askmi/verifier-sdk build`
- `pnpm --filter verifier-backend build`
- `pnpm --filter @askmi/wallet-pwa build`

## Operational Notes

- Local service logs were written to `_qa_logs_sprint1/`; this folder is ignored
  and must not be committed.
- If verifier tests fail after package rename work, rebuild package `dist/`
  before diagnosing source code. Stale build artifacts can still reference old
  package scopes.

## Follow-Up — Done

The five-scenario matrix is now an automated smoke test, so this evidence no
longer depends on manual PowerShell reruns:

- `src/apps/verifier-demo/backend/src/__tests__/wallet-present.smoke.test.ts`

It drives `/wallet-present` for all five scenarios and asserts both sides of the
selective-disclosure guarantee per scenario (requested claims disclosed,
sensitive claims withheld), plus fail-closed `403 REVOKED` for the revoked case.
Trust-list and StatusList2021 lookups are mocked, so the test runs offline with
no local issuer/verifier services.

Run: `pnpm --filter verifier-backend test -- wallet-present.smoke`
