# API & Protocol Reality Audit — 2026-11-03

**Verification date:** 2026-11-03  
**Branch / executable source checked:** `chore/enable-entire` at `f15cf8d` (`master` base `002ce5e`)  
**Scope:** First-principles comparison of 2026 upstream specifications (OpenID4VP 1.0 Final, OpenID4VCI 1.0 Final, OpenID4VC HAIP 1.0 Final, RFC 9901, `draft-ietf-oauth-sd-jwt-vc`, ISO/IEC 18013-5 §9.1.3.6, W3C Digital Credentials API, ETSI TS 119 475, ETSI TS 119 602, EU Age Verification Profile `eu.europa.ec.av.1`, EUDI ARF v3.0.0, EUDI TS07/TS08) against repository documentation and active `src/` implementations.  
**Governance rule (`docs/DOCS_CANON.md`):** This dated record qualifies overlapping claims and paths only. Earlier component tests and QA records retain their validity for their stated scopes. It does not duplicate or replace issues `#170`–`#173` or `#97`.

---

## 1. Upstream Specification Delta (2026 Final Standards vs. Repository Baseline)

| Area | 2026 Upstream Standard | Repository Baseline (`f15cf8d`) | Status / Gap Classification |
|---|---|---|---|
| **Presentation Protocol** | **OpenID4VP 1.0 Final** (2025-07-09) & **HAIP 1.0 Final**: removes DIF Presentation Exchange (`presentation_definition` / `presentation_submission`) in favor of **DCQL (`dcql_query`)** and `vp_token` map `{ [queryId]: [...] }`; removes `client_id_scheme` parameter in favor of **Client Identifier Prefixes** (`x509_san_dns:`, `x509_hash:`, `verifier_attestation:`, `redirect_uri:`, `decentralized_identifier:`); requires `response_uri` (forbids `redirect_uri` in `direct_post` / `direct_post.jwt`); adds `verifier_info` array for RP registration certificates. | `@askmi/oid4vp`, `@askmi/oid4vp-verifier`, and `@askmi/connect` use pre-final DIF Presentation Exchange v2 (`presentation_definition`, `presentation_submission`), `client_id_scheme`, and `redirect_uri`. Zero occurrences of `dcql_query`, `response_uri`, or `verifier_info` in `src/`. | **Protocol generation gap** (tracked for Stage 3 in `docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md`). |
| **Browser Wallet Invocation** | **W3C Digital Credentials API** (`navigator.credentials.get({ digital: { requests: [{ protocol, data }] } })` with `openid4vp-v1-signed`, `openid4vp-v1-unsigned`, `org-iso-mdoc`) + cross-device `openid4vp://` QR. Eliminates the need for an RP to know a user's `walletBaseUrl`. | `@askmi/connect/src/browser/handoff.ts` requires a static `walletBaseUrl` and constructs `<walletBaseUrl>?state=...&nonce=...&request_uri=...`. Zero occurrences of `navigator.credentials.get({ digital })` in `src/`. | **Integration / transport gap** (tracked for Stage 3). |
| **SD-JWT & SD-JWT VC** | **RFC 9901** (2025-11) & **`draft-ietf-oauth-sd-jwt-vc`**: media type `typ: "dc+sd-jwt"` (legacy `vc+sd-jwt` only transitional); RFC 9901 §7.1 requires rejecting the entire presentation if any disclosure is malformed or lacks a matching `_sd` digest; revocation via IETF Token Status List (`statuslist+jwt`). | `src/packages/shared-crypto/src/sd-jwt-vc.ts` issues `typ: "vc+sd-jwt"`, does not enforce `typ` or `algorithms` in `validateSDJWTVC`, silently skips unmatched disclosures via `continue` in `extractDisclosedClaims`, and emits `~~` when zero disclosures are selected in `buildSdJwtPresentation`. | **Reproduced spec compliance defects (`API-03`)** — Stage 0 fix. |
| **OpenID4VCI** | **OpenID4VCI 1.0 Final** (2025-09-16): removes `/batch_credential` in favor of `proofs` array (`jwt`, `attestation`) on `/credential` and dedicated `nonce_endpoint`. | `@askmi/oid4vci` models draft-13 `/batch_credential` and single `proof`. | **Protocol generation gap** (qualifies `EUDI_CIR_MATRIX.md` row `2977-13`). |
| **Age Verification Profile** | **EU Age Verification Technical Specification** (`eu.europa.ec.av.1`, `mso_mdoc`, `age_over_18: true`) and **PID** (`urn:eudi:pid:1` `birthdate` / `age_equal_or_over.18`). Never a static integer `age: 24` claim. | `src/packages/shared-types/src/contracts/claim-contract.ts` already defines canonical `age_over_18` and `birthdate` bindings, and marks `age` as a deprecated alias for `birthdate`. However, `@askmi/connect` (`src/packages/connect/src/core/profile.ts`) and `issuer-mock` (`src/apps/issuer-mock/src/index.ts:236-248`) bypass `claim-contract.ts` and use numeric `age: 24`. | **Internal contract bypass & profile gap (`API-01`, `#97`)** — Stage 0/1 fix. |
| **ISO/IEC 18013-5 DeviceAuth** | **ISO/IEC 18013-5 §9.1.3.6** & **OpenID4VP 1.0 Appendix B.2.6.1**: COSE_Sign1 over `DeviceAuthenticationBytes = Tag24(CBOR(["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]))` as **detached payload (`payload: null`)** with empty `external_aad` (`<< >>`), using `OpenID4VPHandover` / `OpenID4VPDCAPIHandover`. | `src/packages/mdoc/src/device-auth.ts:39-101` passes `encode(sessionTranscript)` as `externalAad`, embeds `{ docType, deviceNameSpaces }` as non-detached payload, and rejects `result.payload === null`. | **Reproduced spec inversion (`API-04`)** — Stage 0 fix. |
| **RP Registration & Trust Lists** | **ETSI TS 119 475** (WRPAC / WRPRC certificates) & **ETSI TS 119 602** (LoTE JSON/JWS schema); **EUDI TS07 / TS08** (erasure and DPA reporting via WRPRC contact URIs and OS external handlers). | `trust-list-resolver.ts` uses a custom JSON format and defaults `anchorPublicKey` to `null` (`verified: true` without cryptographic verification); `WalletService.requestDataErasure` / `reportRelyingParty` post custom `askmi-poe` tokens to HTTP endpoints. | **Component / schema gap (`API-05`, `API-07`)** — qualifies `EUDI_CIR_MATRIX.md` rows `2982-15`..`2982-17`. |

---

## 2. Reproduced Code & Integration Findings (`f15cf8d`)

### `API-01` — 4-Way Live Browser E2E Break across `@askmi/connect`, `verifier-demo`, `wallet-pwa`, and `issuer-mock`
**Scope:** Live browser interaction between `verifier-demo` (`:5175` / `:3004`), `wallet-pwa` (`:5174`), and `issuer-mock` (`:3005`) introduced in PR `#224` (extends `#170` integration scope; does not invalidate the isolated unit/HTTP regression suites recorded in `docs/qa/CONNECT_PROFILE_INTEGRATION_2026-10-25.md`).

1. **HTTPS vs. HTTP + CORS Mismatch:**
   - `src/apps/wallet-pwa/vite.config.ts:6,14` enables `@vitejs/plugin-basic-ssl` (`https://localhost:5174`).
   - `src/apps/verifier-demo/backend/src/app.ts:470` defaults `walletBaseUrl` to `http://localhost:5174`.
   - `dev-demo.ps1:39` sets `CORS_ALLOWED_ORIGINS="http://localhost:5174,http://localhost:5175"`, rejecting browser `fetch()` requests from origin `https://localhost:5174`.
2. **Handoff URL Drops Wallet Entry Parameter (`demo=wallet`):**
   - `src/packages/connect/src/browser/handoff.ts:40-49` generates `<walletBaseUrl>?state=...&nonce=...&request_uri=...` without `demo=wallet`.
   - `src/apps/wallet-pwa/src/App.tsx:2452-2466` renders `<LandingPage>` unless `demo=wallet` is present (or the user manually clicks into the wallet, which calls `window.history.replaceState({}, '', url.toString())` without preserving the Connect query parameters).
3. **Policy Engine Deterministic `DENY` (`CLAIM_NOT_ALLOWED`) on `$.age`:**
   - `src/packages/connect/src/core/profile.ts:25-84` requests DIF PE path `$.age` (`vct: "https://askmi.demo/vct/age-credential"`).
   - `src/apps/wallet-pwa/src/App.tsx:1131-1137` extracts path segments from `authRequest.presentation_definition` into `requestedClaims: ['age']` and `requestedProvenClaims: []`.
   - `src/apps/wallet-pwa/src/data/DemoPolicy.ts:71-81` configures rule `liquor-store` (`did:askmi:verifier-liquor-store`) with `allowedClaims: []` and `provenClaims: ['age >= 18']`.
   - `src/packages/policy-engine/src/engine.ts:270-274` checks every entry in `requestedClaims` against `selectedRule.allowedClaims` (`[]`) and returns `DENY` with `DenyReasonCode.CLAIM_NOT_ALLOWED`.
   - *Why unit tests missed this:* `src/apps/wallet-pwa/src/App.test.tsx:972` called `bootstrapFetchMocks('ALLOW')`, mocking `WalletService.evaluateRequest` to return `ALLOW` instead of executing `PolicyEngine.evaluate()` with `DemoPolicy`.
4. **Issuer `iss` Mismatch between `issuer-mock` and `verifier-demo`:**
   - `src/apps/issuer-mock/src/index.ts:48,243` issues credentials with `iss: 'did:web:localhost%3A3005'`.
   - `src/apps/verifier-demo/backend/src/app.ts:46,435` checks `if (!issuerId || issuerId !== CONFIGURED_ISSUER)` where `CONFIGURED_ISSUER` defaults to `'https://issuer.askmi.demo'`, rejecting credentials from `issuer-mock` unless environment variables are manually overridden.

---

### `API-02` — Policy-Engine Disclosure Clipping Bypass in `wallet-pwa` (`presentOID4VP`)
**Location:** `src/apps/wallet-pwa/src/App.tsx:959-961`  
**Observation:** After `WalletService.evaluateRequest()` returns a `DecisionCapsule` whose `authorized_requirements` array contains only the policy-approved subset of claims, `presentOID4VP` ignores `result.decisionCapsule.authorized_requirements` and re-extracts all verifier-requested fields directly from `authRequest.presentation_definition`:
```ts
const requestedClaimNames = authRequest.presentation_definition.input_descriptors
  .flatMap((d) => d.constraints?.fields ?? [])
  .flatMap((f) => f.path.map((p) => p.replace(/^\$\.?/, '').split('.')[0]).filter(Boolean));
```
If a verifier requests an allowed claim alongside an unallowed claim and the policy engine clips or prompts on a subset, `presentOID4VP` discloses all claims requested in `authRequest.presentation_definition`.

---

### `API-03` — RFC 9901 SD-JWT VC Validation & KB-JWT Verification Gaps
**Locations:**
- `src/packages/shared-crypto/src/sd-jwt-vc.ts:145-157`: `validateSDJWTVC` calls `jwtVerify(compactJWS, issuerPublicKey)` without checking header `typ` (`dc+sd-jwt` / `vc+sd-jwt`) or restricting `algorithms`.
- `src/packages/shared-crypto/src/sd-jwt-vc.ts:404-418`: `extractDisclosedClaims` silently executes `continue` when a disclosure string is malformed (`arr.length < 2`) or when its SHA-256 digest is absent from the issuer's `_sd` array, violating RFC 9901 §7.1 (which requires rejecting the entire SD-JWT presentation if any disclosure cannot be verified).
- `src/packages/shared-crypto/src/sd-jwt-vc.ts:465`: `buildSdJwtPresentation` joins `[ packageObj.issuerJwt, selected.join('~'), packageObj.kbJwt ?? '' ].join('~')`, emitting an invalid double tilde `~~` whenever `selected` is empty (`0` disclosures).
- `src/packages/oid4vp-verifier/src/response-verifier.ts:38-48,197`: `verifyCredentialSignatures` is optional (`undefined`/falsy by default), and line `197` (`if (lastSegment.length > 0 && isCompactJWT(lastSegment))`) only validates the Key Binding JWT if a non-empty trailing segment is present — allowing a presentation with a trailing `~` (`lastSegment === ''`) to skip KB-JWT verification even when `expectedNonce` or `cnf` is present.

---

### `API-04` — Inverted ISO/IEC 18013-5 §9.1.3.6 `DeviceAuthentication` COSE Structure
**Location:** `src/packages/mdoc/src/device-auth.ts:39-101`  
**Observation:** `signDeviceAuth` and `verifyDeviceAuth` pass `encode(sessionTranscript)` as `externalAad` into `coseSign1Sign` / `coseSign1Verify`, encode `{ docType, deviceNameSpaces }` as an inline COSE payload, and reject `result.payload === null` (`throw new Error('COSE_Sign1 payload is null')`). Under ISO/IEC 18013-5 §9.1.3.6, `DeviceAuth` (`deviceSignature`) MUST be a detached-payload (`payload: null`) `COSE_Sign1` over `DeviceAuthenticationBytes = Tag24(CBOR(["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]))` with empty `external_aad`.

---

### `API-05` — Unverified Default Trust Lists, Status Lists, and Server-Side WebAuthn Assertions
**Locations:**
- `src/packages/shared-crypto/src/trust-list-resolver.ts:121,159-162`: `anchorPublicKey` defaults to `null`; when `null`, `fetchAndVerify()` skips JWS verification (`// No anchor key configured — accept without cryptographic verification`) while returning `verified: true`. Line `121` also serves expired cached trust lists for up to 4 hours (`GRACE_PERIOD_MS`) even when `riskTier === 'high'`, contradicting the docstring (`high = fail immediately on expired`).
- `src/packages/revocation-statuslist/src/index.ts:185-212`: `StatusListResolver.resolve()` parses raw JSON and inflates `encodedList` without verifying any issuer signature on the status list credential.
- `src/packages/webauthn-verifier/src/index.ts:129-168`: Server-side `verifyAssertion()` checks challenge, origin, `rpIdHash`, flags, and sign counter, but never verifies `signedAssertion.response.signature` against `stored.publicKeyCose` (distinct from the wallet-side passkey verification closed in `#218`).

---

### `API-06` — Inaccurate Library Citation in `docs/_core/03_ARCHITECTURE.md`
**Location:** `docs/_core/03_ARCHITECTURE.md:10`  
**Observation:** Claims `Libraries: @sd-jwt/core, @sd-jwt/decode, @sd-jwt/present, @sd-jwt/verify, jose`. A repository-wide search (`git grep "@sd-jwt/"`) confirms zero `@sd-jwt/*` packages exist in any `package.json` or source file; SD-JWT VC is implemented in-house in `@askmi/shared-crypto` using `jose` and WebCrypto.
