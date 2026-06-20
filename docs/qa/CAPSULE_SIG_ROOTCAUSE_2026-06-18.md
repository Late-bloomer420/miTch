# QA Evidence — "Capsule Signature Verification Failures" Root-Cause & Resolution

**Date:** 2026-06-18 (recorded into repo 2026-06-20 as part of H-10 truth alignment)
**Scope:** The recurring "capsule signature verification failures" reported across the 5 demo
scenarios (liquor-store, doctor-login, ehds-er, pharmacy, OID4VCI/revoked) on 2026-06-15…17.
**Verdict:** Not a cryptographic defect. Root cause was an **incomplete AskMI↔miTch rebrand**
(DID namespace + package-scope drift). The drift was already corrected in source; this note
records the root cause and the live end-to-end verification so it is repo truth, not just a
local agent memory.

---

## 1. Real captured error (not "signature failed")

Source: `_qa_logs_sprint1/verifier.err.log` (run 2026-06-06):

```
[Verifier] /present verification failed: AADValidationError:
  AAD Binding Violation: Package addressed to did:askmi:verifier-liquor-store,
  expected did:mitch:verifier-liquor-store
```

Companion symptoms in the same run:
- `wallet.err.log`: Vite import-resolution failures mixing `@askmi/*` and `@mitch/*`
  (e.g. `@askmi/mdoc` vs `@mitch/mdoc`, `@mitch/policy-engine`).
- `issuer.err.log`: `EADDRINUSE :3005` (a stale issuer process, not a crypto error).

## 2. Why it *looked* like a signature failure

The transport capsule is authenticated encryption (AEAD): the recipient verifier DID is bound
as **AAD (Additional Authenticated Data)**. When the wallet addressed the capsule to
`did:askmi:…` while the verifier was configured to expect `did:mitch:…`, the AEAD integrity
check failed. That surfaces as a verification/"signature" failure but is really an
**identity-namespace mismatch** — a rename that had landed on one side of the flow but not the
other. Verifier AAD check: `src/packages/verifier-sdk/src/VerifierSDK.ts` (`AADValidationError`
when `aad_context.verifier_did !== this.config.verifierDid`).

## 3. Current source state (verified 2026-06-18, re-confirmed 2026-06-20)

- `did:mitch:` occurrences in `src/`: **0**. `@mitch/*` imports in `src/`: **0**.
- `pnpm guard:rebrand` (`scripts/guard-active-rebrand.mjs`): **passes**.
- `verifier-demo` uses `did:askmi:verifier-liquor-store` for **both** identity and
  `expectedAud` (`ASKMI_DEMO.verifierDid`) — the two sides now agree.
- No `dist/` artifact carries `did:mitch`. Dev runs from source (`tsx watch`).

## 4. Live end-to-end verification (2026-06-18)

All 4 servers up via `start-4-servers.ps1` (issuer :3005, verifier-backend :3004, wallet :5174,
verifier-frontend :5175). Drove the real presentation path `POST :3004/wallet-present`
(full SD-JWT presentation + `validateSDJWTPresentation`: signature + revocation + trust):

| Scenario | Result | Disclosed claims |
|---|---|---|
| liquor-store | ok | `age` |
| doctor-login | ok | `age, role, licenseId` |
| ehds-er | ok | `bloodGroup, allergies, emergencyContacts` |
| pharmacy | ok | `medication, dosageInstruction, refillsRemaining` |
| revoked | HTTP 403 `{"errors":["REVOKED"]}` | correct revocation deny (not a sig/AAD error) |

## 5. Supporting automated evidence (2026-06-18 / re-run 2026-06-20)

Package suites covering the capsule/AAD/crypto path, all green:
- `shared-crypto` 266, `verifier-sdk` 59 (incl. AAD logic), `integration-tests` 54,
  `verifier-demo` backend 96 (e2e `/wallet-present` + `/present`).
- Full monorepo: **46/46 turbo test tasks green** (2026-06-20).

## 6. Residual / not-blocking follow-ups

- Optional fail-fast startup assertion that issuer/verifier/wallet DIDs share one namespace,
  so a future half-rebrand fails loudly at boot instead of as a cryptic AEAD error.
- Optional CI smoke that drives the 5-scenario `/wallet-present` sweep so namespace drift
  cannot silently regress.

Neither is a pilot blocker; `docs/pilot/FINDINGS_BACKLOG.md` has no open findings.
