# ADOPT-0a/0b Live End-to-End Verification — 2026-07-17

> **Role:** Dated internal QA/evidence record (per `docs/DOCS_CANON.md`). It
> records a local live run against one exact revision. It is not current-readiness
> evidence, external validation, certification, or production proof. Read it with
> [AskMI maturity and known limitations](../MATURITY_AND_LIMITATIONS.md) and the
> [release-candidate checklist](../RELEASE_CANDIDATE_CHECKLIST.md). Later changes
> do not retroactively inherit these results.

**Revision verified:** `bb340038fdd4df98c6d2f2936f2a39ba7c872ac1` (`fix(adopt-0b): verifier decodes SD-JWT disclosures + issuer issues the requested claim (real e2e) (#137)`)
**Verification date:** 2026-07-17
**Evidence labels:** implemented/repository-tested on the named revision; local demo-only; externally unvalidated.
**Scope:** the credential path shipped by ADOPT-0a (#135), ADOPT-0b (#136), and the #137 correctness fix — issuance, wallet storage APIs, selective-disclosure presentation, and verifier validation. The live probe covered issuance, presentation construction, and verifier validation; wallet-pwa browser storage and UI were not live-driven.

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
current source). A throwaway probe drove the same backend endpoints and
presentation-builder sequence used by wallet-pwa. It did not drive wallet-pwa
browser UI, IndexedDB, or the QR/deep-link handoff:

1. `POST http://localhost:3005/credential` with a real holder-proof JWK → real
   `vc+sd-jwt` credential (holder-bound `cnf`, `_sd` disclosures for `age` /
   `dateOfBirth` / `isOver18`).
2. `buildSdJwtPresentation(credential, ['age'], holderKey, {aud, nonce})` → selective
   disclosure of only `age` + KB-JWT.
3. `POST http://localhost:3004/oid4vp-present` → verifier resolves the issuer key from
   the running **local development trust-list endpoint**
   (`did:web:localhost%3A3005` ∈ `/v1/eudi-lotl.json`) + issuer JWKS, verifies the
   signature, decodes disclosures (#137), and returns the result.

### Results

| Case | Live result | Bounded conclusion |
|------|-------------|--------------------|
| **Happy path** | `200 {ok:true, disclosedClaims:{age:24}, consentReceipt:{claimsShared:["age"]}}` | The local issuer, presentation builder, development trust/JWKS resolution, signature check, and #137 disclosure decode worked together for this fixture on the named revision. |
| **Circular-verification negative case** | attacker forges a credential claiming trusted `iss did:web:localhost%3A3005`, signs with their own key, and supplies their own `issuer_jwk` → `403 {ok:false, errors:["Signature verification failed"]}` | In this tested route and case, the verifier used the configured issuer JWKS rather than the wallet-supplied key. |
| **Fail-closed trust-gate negative case** | credential from `did:web:evil.example` → `403 {error:"untrusted_or_unresolvable_issuer"}` | The tested unknown issuer was rejected before signature verification. |

These three exercised the two repository trust checks (`checkTrust:true` at `high`
assurance inside `validateSDJWTPresentation`, plus
`defaultResolveIssuerKey`'s own trust check) using local development trust
material. They did not establish national EUDI issuer interoperability, official
profile conformance, or independent cryptographic assurance. The committed unit
e2e (`real-presentation-e2e.test.ts`, `checkTrust:false`) did not cover those
trust-list checks.

The live probe required running services and was deleted after the run, so this
record is a historical observation rather than a rerunnable RC gate. The crypto
chain remains repository-tested in
`src/packages/oid4vp/src/__tests__/real-presentation-e2e.test.ts` (2/2 on the
named revision).

---

## VERIFIED ON THE NAMED REVISION

- **Live-observed path:** issuer-mock issued a holder-bound `vc+sd-jwt`; the
  presentation builder selectively disclosed `age` with a KB-JWT; and
  `/oid4vp-present` validated the presentation through the configured local
  trust-list/JWKS path and returned a consent receipt.
- **Repository-tested wallet behavior:** ADOPT-0a (#135) added
  `addSdJwtVc`/`getSdJwtVc`; ADOPT-0b (#136) + #137 present from the stored
  credential and decode its disclosures. The live probe did not independently
  exercise browser IndexedDB or the wallet UI around those APIs.
- **Fabrication boundary:** generated scenario claims and ephemeral issuer keys
  were absent from the specific wallet-pwa ADOPT presentation path tested in code;
  the separate verifier-demo frontend path remained simulated, as recorded below.
- **Negative cases:** the tested forged-key case failed signature verification, and
  the tested unknown issuer failed closed at the trust gate.
- **Regression suite:** `pnpm test` → 47/47 Turbo tasks green as of #137. This is a
  dated repository result, not a current-checkout guarantee.

## OPEN / KNOWN GAPS

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


---

## Relationship to the current truth/readiness RC baseline

This record was reconciled on 2026-08-26 against PR #141 at baseline revision
`eb3cf433f63a7317a14c9f265308bdf51415dc6d`. PR #141 established the current
maturity vocabulary and recorded separate, repository-resolvable validation
revisions for its CORS, session-continuity, recovery, dependency, and
documentation changes. Those later results do not
retroactively expand this 2026-07-17 run, and this record does not expand the RC
claims.

The current baseline still treats independent security and cryptographic review,
official EUDI conformance/interoperability evaluation, production key management,
distributed verifier-session storage, trust governance, monitoring, incident
response, and support ownership as open. See
[`MATURITY_AND_LIMITATIONS.md`](../MATURITY_AND_LIMITATIONS.md) and
[`RELEASE_CANDIDATE_CHECKLIST.md`](../RELEASE_CANDIDATE_CHECKLIST.md).
