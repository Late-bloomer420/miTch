# Connect numeric-age integration evidence — 2026-10-25

## Revision and configuration

Code revision: `2191ca38ff3d537d51315e83c1f2cfeb682a5d9b`, integrating
Connect implementation `976baf0e49bbcaa57516126d39cc21cd615b9be5` with master
`4b7e393`. Runtime: Windows, Node 24.16.0, pnpm 9.15.9.
Profile: `age-liquor-store-v1`, numeric age >= 18, age credential VCT,
real P-256 issuer/holder signatures with a synthetic trusted issuer.
Store: dedicated `InMemoryAskMIConnectSessionStore` in one backend process.

The earlier active `/oid4vp-present` fix landed in #208 at
`a65774d39413f5e2c59771d67095b565fc3cda05`; its post-merge checks passed.
Its [original dated evidence](ACTIVE_AGE_PROFILE_2026-10-25.md) remains unchanged.
This record covers the remaining Connect profile and application integration.

## Implemented path

`POST /askmi/connect/sessions` creates the immutable request snapshot; the handoff
points to `GET .../:id/request`. The wallet loads and checks those bindings,
applies the existing consent flow and presents its stored SD-JWT with holder
binding. `POST .../:id/presentation` reserves the attempt once and validates the
stored request, issuer/holder signatures, exact submission, VCT and claim scope.
The verifier's `?flow=connect` panel polls the minimized status and shows success
only for `verified` plus `eligible: true`. Legacy simulated responses cannot
complete this separate store. Failed wallet responses produce DENIED receipts.

The configured single JWKS is bound to `ISSUER_DID` (default demo issuer), in
addition to the trust-list check. Another trust-listed issuer cannot borrow that
key. Resolver exceptions persist terminal failure with HTTP 503; retry requires
a fresh session. Old sessions without the original request fail closed.

## Reproducible checks

- `pnpm install --offline --frozen-lockfile`: passed.
- `pnpm exec turbo run build --filter=verifier-backend... --filter=@askmi/wallet-pwa... --filter=verifier-frontend...`:
  18/18 tasks passed (14 cached); wallet chunk-size warning remains.
- `pnpm lint`: 13/13 tasks passed (8 cached); seven existing wallet `any` warnings, zero errors.
- `pnpm run test -- --concurrency=1`: in progress; final outcome is not yet claimed.

The signed HTTP regression matrix is in
`src/apps/verifier-demo/backend/src/__tests__/connect-route.test.ts` (16 cases):
valid age with minimized results; replay/terminal request; underage, missing and
wrong-type age; extra name and prototype pollution; wrong VCT/submission/state;
crossed sessions/nonce; wrong audience; untrusted issuer; invalid holder binding;
concurrent attempts; expiry; resolver errors; simulated-route isolation; and the
actual wallet SD-JWT disclosure format with both allowed and excess claims.
`issuer-key-binding.test.ts` additionally proves configured-issuer/JWKS binding.
The issuer-binding test failed before the correction and passed after it.
Connect package tests cover the core/adapter/lifecycle contracts; wallet
`connect-handoff.test.ts` covers stored-request bindings and success semantics.

On implementation revision `976baf0`, a local headless Edge smoke used the actual
Connect backend on port 3304 and verifier frontend on port 5275, with a synthetic
trusted issuer. It clicked Start, read the handoff, fetched the server request,
submitted real signed wallet-format SD-JWTs and observed the polled UI. Age 24
showed eligibility confirmed; age 12 showed verification failed. Neither UI
showed raw age or a proof-only assurance. This did not exercise wallet onboarding,
passkey interaction or the entire wallet UI; those are not claimed as browser E2E.

An earlier full run before integrating #211 failed on the existing backend
5-second app-import timeout. The merged #211 sets the backend timeout to 30s;
that initial failure is not represented as a successful run.

## Deployment and assurance limits

Set `VERIFIER_BASE_URL` and `WALLET_BASE_URL` to the browser-reachable origins
(default localhost:3004 and localhost:5174), configure the existing CORS allowlist,
and bind `ISSUER_DID`/`ISSUER_BASE_URL` to the intended issuer and JWKS.
The demo frontend uses its hostname on backend port 3004. LAN/proxy deployments
must configure these values consistently; local test resolver injection is not
a production trust source or public bypass endpoint.

The middleware receives numeric age. Only the application/status projection is
minimized; no boolean credential, ZKP, full erasure or unlinkability assurance is
established. Single-process reservation does not establish distributed atomicity,
durability or restart recovery. Synthetic issuer tests do not establish official
wallet interoperability, external security assurance or production readiness.
#97, #171–#173, #185 and the pilot/release gates are unchanged.
