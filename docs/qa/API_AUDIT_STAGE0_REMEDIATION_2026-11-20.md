# API audit Stage 0 remediation — 2026-11-20

**Tracks:** findings `API-01`..`API-05` of [`API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](API_PROTOCOL_REALITY_AUDIT_2026-11-03.md),
state per sub-finding as reviewed in [`API_AUDIT_REVIEW_2026-11-18.md`](API_AUDIT_REVIEW_2026-11-18.md).
**Base:** `master` @ `cd50806`. **Branch:** `claude/eloquent-fermi-xmfqun`, head as recorded in the PR.
**Runtime:** Node v22.23.5, pnpm 10.34.9, Linux container, Chromium 1243 (headless) for the browser check.
**Method:** code fixes with tests; every new negative test was also run against the previous source
and failed there (recorded below as "fails on old code"). Not a security PASS, not an external
review, no gate moves. `API-06` (docs) was closed earlier; `API-07` (protocol generation) is
Stage 1–3 work and unchanged.

## 1. Result per sub-finding

| ID | State after this branch | Where fixed | Proof |
|---|---|---|---|
| API-01.1 HTTPS wallet vs HTTP CORS | fixed on master | #265 | browser check §3 |
| API-01.2 handoff without `demo=wallet` | fixed on master | #277 (`walletRoute` owns handoff) | browser check §3 |
| API-01.3 `$.age` denied by `DemoPolicy` | fixed for the demo wallet on master; see §4 | #277 (`ISOLATED_DEMO_POLICY`: numeric age only after consent) | `demo-policy.test.ts`, browser check §3 |
| API-01.4 `iss` mismatch issuer-mock vs verifier | **fixed here** | `e0b1be8`: `ASKMI_DEMO.issuerUri` = issuer-mock DID, issuer-mock reads it | `issuer-mock/src/index.test.ts` "API-01.4" |
| API-02 disclosure clipping bypass (P0) | **fixed here** | `933e9cd`: `presentOID4VP` discloses only `authorized_requirements[].allowed_claims` ∩ request; none → nothing presented | `wallet-pwa/src/__tests__/authorized-disclosure.test.ts` (real WalletService/PolicyEngine + real SD-JWT, no evaluate mock) |
| API-03a `typ`/`alg` | **fixed here** | `095581e`: `typ` ∈ {`dc+sd-jwt`,`vc+sd-jwt`}, alg ∈ ES256/ES384/ES512/EdDSA | `shared-crypto/test/sd-jwt-vc-api03.test.ts` — 5/7 fail on old code |
| API-03b lenient disclosures | fixed on master | #288 (`extractDisclosedClaimsStrict` on the active path) | #288 tests |
| API-03c `~~` on zero disclosures | already correct on master; now pinned | `095581e` (test only) | same file, "API-03c" — passes on old and new code |
| API-03d KB-JWT skippable | **fixed here** | `15052d2`: with signature verification on, a missing KB-JWT fails closed | `oid4vp-verifier/.../response-verifier.crypto.test.ts` "API-03d" — 2 fail on old code |
| API-04 mdoc DeviceAuthentication | **fixed here** | `7f6091f`: detached payload, empty AAD, `DeviceAuthenticationBytes` incl. docType + DeviceNameSpaces | `mdoc/test/device-auth.test.ts` "API-04" — 3 fail on old code |
| API-05a/b trust list unverified / high-risk grace | fixed on master | #276 | `shared-crypto/src/trust-list-mode.test.ts` |
| API-05c status list unsigned | **fixed here** | `b462adc`: live mode requires a signed VC-JWT from the resolved issuer key | `revocation-statuslist/.../signed-status-list.test.ts` — 3 fail on old code; `issuer-mock/src/status-list.test.ts` |
| API-05d server WebAuthn signature | **fixed here** | `97143c5`: signature, rpIdHash, UP+UV, type, challenge, origin, counter via `@simplewebauthn/server` | `webauthn-verifier/.../verifier.test.ts` "API-05d" — 5 fail on old code; integration full-stack test now signs for real |

The integration test `E2E: WebAuthn + Policy + Revocation (Full Stack)` previously asserted
`verified: true` for `mock-public-key-placeholder` + `mock-signature`. It reproduced API-05d as a
passing test. It now uses a real ES256 key and contains a forged-signature negative.

## 2. Commands and results (branch head before docs commit, `e0b1be8`)

| Command | Result |
|---|---|
| `pnpm build` | 31/31 tasks |
| `pnpm test` | 49/49 tasks, 2658 tests passed across 31 Vitest runs, 0 failed |
| `pnpm lint` | 13/13 tasks; 7 warnings in wallet-pwa (existing) |
| `pnpm demo` + `scripts/demo-wallet-smoke.mjs` | `PASS` (see §3) |

Per-package focused runs during the work (same revision family): wallet-pwa 289, shared-crypto 351,
oid4vp 101, oid4vp-verifier 65, revocation-statuslist 34, webauthn-verifier 25, mdoc 195,
issuer-mock 25, verifier-backend 296, integration-tests 54, connect 66 — all passed.

## 3. Browser check (API-01, live path)

`pnpm demo` (issuer 3005, verifier 3104, store 5185, demo wallet 5184), then the smoke script from
#277 in headless Chromium with a virtual passkey. The only deviation from the committed script:
`chromium.launch({ headless: true, executablePath: '/opt/pw-browsers/chromium' })` instead of
`channel: 'chrome'` (no Chrome channel in this container), run from a temporary copy that was
deleted afterwards.

Output: `PASS: store handoff, virtual-passkey enrollment, mock issuance, consent-before-presentation,
verified eligibility, demo database, decline, built-in age check and malformed link.`

This exercised the API-02 change (presentation built from the DecisionCapsule) and the API-01.4
default issuer end to end. The verifier ran with `ASKMI_TRUST_MODE=dev` (set by its `dev.ts`).

## 4. Known limits and owner decisions (not closed by this record)

- **API-01.3 for the regular wallet (5174):** `DEMO_POLICY` still allows only the predicate
  `age >= 18` for `did:askmi:verifier-liquor-store`, so a Connect request for numeric `$.age`
  against that wallet is denied by design. The audit's suggested change (Connect requests
  `age_over_18` via `claim-contract.ts`) is the profile decision held open under #97; it is not
  made here.
- **API-04:** DeviceNameSpaces is re-encoded from the parsed map. A wallet whose original encoding
  differs would not verify until the parser keeps the raw `DeviceNameSpacesBytes`. EMacKey
  derivation and `OpenID4VPHandover` were not changed. wallet-pwa still emits a mock
  `deviceSignature` (`WalletService.ts`, mdoc presentation) — a holder-side gap, separate from the
  verifier structure fixed here. No mdoc route is active.
- **API-05c:** live mode is the default whenever `ASKMI_TRUST_MODE` is not `dev`. Unsigned status
  lists then fail closed (DENY). Callers of `@askmi/revocation-statuslist` that relied on unsigned
  JSON must set `statusListMode: 'dev'` or serve a signed list. The active SD-JWT credential from
  issuer-mock carries no `status` claim, so the active route does not reach this check today.
- **API-05d:** user verification (UV) is now required. Authenticators that assert presence only
  are rejected. Package has no importer outside `integration-tests`.
- **API-03d:** structural mode (`verifyCredentialSignatures` false, the default) is unchanged and
  still reports `signaturesVerified: false`; making it the default would change the public API.
- **API surface:** `verifyDeviceSignature`/`verifyDeviceMac` gained a required `docType` parameter
  (no importer outside `@askmi/mdoc` tests). All other API changes are additive options/exports.
  Owner approval is requested in the PR per CLAUDE.md.
- **API-07** and Stages 1–3 of the v2 plan are untouched.
