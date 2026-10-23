# ADOPT-0a/0b Live End-to-End Verification — 2026-07-17

> **Role:** Dated QA/evidence record (per `docs/DOCS_CANON.md`). Captures what was
> actually run against **live servers on current `master`**, what is **DONE**, and
> what remains **OPEN / KNOWN GAP**. Grounded in real facts, not assumption.

**Master verified:** `bb34003` (`fix(adopt-0b): verifier decodes SD-JWT disclosures + issuer issues the requested claim (real e2e) (#137)`)
**Scope:** the real credential path shipped by ADOPT-0a (#135), ADOPT-0b (#136) and the #137 correctness fix — issuance → storage → selective-disclosure presentation → verifier validation.

---

## Why this record exists

ADOPT-0b (#136) passed every unit test but did **not** work end-to-end; #137 fixed
two bugs (verifier ignored SD-JWT disclosures; requested claim `age` was never
issued). That taught us that "unit-green" ≠ "works". This pass therefore drives the
**real HTTP routes against running servers**, not isolated functions.

## Real-facts finding: stale zombie servers were masking the merged code

On first probe, the verifier on `:3004` returned `400 {"error":"Missing issuer_jwk"}`
— a string that **does not exist anywhere in current source** (the merged route
resolves the issuer key from the trust list and ignores any wallet-supplied
`issuer_jwk`). Investigation: the `:3004` and `:5174` listeners were **3-day-old
processes from 2026-07-14** (`StartTime 07/14 00:48:12`), i.e. pre-merge code left
running from an earlier session. They were killed and the servers restarted fresh
from current `master`. **Lesson:** always confirm the running process is current
before trusting a live demo.

## What was driven (live, fresh current-`master` servers)

Servers: `issuer-mock :3005`, `verifier-backend :3004` (both `tsx watch src` from
current source). A throwaway probe drove the exact HTTP calls the wallet-pwa makes:

1. `POST http://localhost:3005/credential` with a real holder-proof JWK → real
   `vc+sd-jwt` credential (holder-bound `cnf`, `_sd` disclosures for `age` /
   `dateOfBirth` / `isOver18`).
2. `buildSdJwtPresentation(credential, ['age'], holderKey, {aud, nonce})` → selective
   disclosure of only `age` + KB-JWT.
3. `POST http://localhost:3004/oid4vp-present` → verifier resolves the issuer key from
   the **live trust list** (`did:web:localhost%3A3005` ∈ `/v1/eudi-lotl.json`) + issuer
   JWKS, verifies the signature, decodes disclosures (#137), returns the result.

### Results

| Case | Live result | Proves |
|------|-------------|--------|
| **Happy path** | `200 {ok:true, disclosedClaims:{age:24}, consentReceipt:{claimsShared:["age"]}}` | Real issuance → real selective disclosure → trust-list issuer-key resolution → #137 disclosure decode all work together |
| **Circular-verification closed** | attacker forges a cred claiming trusted `iss did:web:localhost%3A3005`, signs with their own key, and supplies their own `issuer_jwk` → `403 {ok:false, errors:["Signature verification failed"]}` | Verifier resolves the **real** issuer key from JWKS and ignores the wallet-supplied key |
| **Fail-closed trust gate** | cred from `did:web:evil.example` → `403 {error:"untrusted_or_unresolvable_issuer"}` | Untrusted issuer is rejected before signature check |

These three exercise the two trust-list checks (`checkTrust:true` at `high` assurance
inside `validateSDJWTPresentation`, plus `defaultResolveIssuerKey`'s own trust check)
that the committed unit e2e (`real-presentation-e2e.test.ts`, `checkTrust:false`) did
**not** cover.

The probe itself was a throwaway (requires live servers) and was deleted after the
run; the crypto chain remains covered in CI by
`src/packages/oid4vp/src/__tests__/real-presentation-e2e.test.ts` (2/2).

---

## DONE (verified)

- **ADOPT-0a (#135):** issuer-mock issues a real `vc+sd-jwt` (holder-bound `cnf`,
  `_sd` selective-disclosure digests); wallet stores it (`addSdJwtVc` /
  `getSdJwtVc`). Issuer key resolves via the trust list — a real issuer (Austria ID
  / eIDAS) can be plugged in without code changes.
- **ADOPT-0b (#136) + #137:** wallet presents from the **stored** credential with
  real selective disclosure + KB-JWT; verifier `/oid4vp-present` resolves the issuer
  key authoritatively and decodes disclosures. No fabrication (ephemeral issuer keys,
  scenario claims) remains in the wallet present path.
- **Circular-verification gap closed:** the verifier never trusts a wallet-supplied
  `issuer_jwk` (proven live above).
- **Regression suite:** `pnpm test` → 47/47 turbo tasks green as of #137.

## OPEN / KNOWN GAP (honest)

- **Only the `age` (liquor-store) scenario works end-to-end with a real credential.**
  The wallet holds only an `AgeCredential`; doctor / EHDS / pharmacy scenarios
  correctly **fail-closed** ("no matching credential") rather than presenting. Broad
  multi-credential coverage is future work.
- **Browser UI click-through not automated.** This pass verified the real HTTP path
  the wallet-pwa uses; the wallet-pwa UI (HTTPS self-signed `:5174`, IndexedDB,
  in-browser OID4VCI + QR handoff) was **not** driven in an automated browser. The
  wiring around those exact calls is covered by `WalletService` / `App` unit tests,
  but a manual browser click-through remains a residual QA item.
- **`pnpm dev` still fails on `@askmi/poc-hardened`** (`ERR_MODULE_NOT_FOUND`) even
  after #133 added `dev dependsOn ^build`. Start the demo individually
  (`pnpm --filter issuer-mock dev`, `pnpm --filter verifier-backend dev`) or with
  `--filter=!@askmi/poc-hardened`. The `poc-hardened` package is an isolated PoC, not
  part of the demo path.
- **The verifier-demo *frontend* (`:5175`) `/wallet-present` path is still the
  simulated wallet** (ephemeral issuer keys + scenario claims). It is a demo-only
  visualization and is **not** the real ADOPT-0a/0b path; the real path is
  wallet-pwa → issuer-mock → verifier `/oid4vp-present`.
- **Carried-over minor gaps (from ADOPT-0a/0b ledger):** issuer-mock returns 500 (not
  400) for a non-P-256 holder JWK; `x-correlation-id` is dropped on the OID4VCI fetch
  (G-100 trace gap); `generateHolderBinding` extractable-key convergence.
