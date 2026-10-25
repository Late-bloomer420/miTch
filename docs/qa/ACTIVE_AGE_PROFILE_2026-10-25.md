# Active numeric-age route — 2026-10-25

Issue #170, bounded active-route slice. Executable revision:
`c4c18ce77981adf2f2057ecf3adbfecaee7775b5`, Windows, Node `v24.16.0`, pnpm `9.15.9`.
Baseline `33a9876` already includes #195's server-owned nonce/state binding.
This record supplements, rather than rewrites, the 2026-10-14 observations.

## Scope and behavior

`verifier-demo/backend` retains a detached original authorization request and
synchronously reserves each response attempt before asynchronous issuer lookup.
Failed, malformed and successful attempts cannot be retried under that authorization.
Reset or a new authorization creates a fresh attempt. Late work cannot commit after
reset, request replacement or expiry. This is a single-process in-memory topology;
it is not a distributed or durable session-store guarantee.

The real `/oid4vp-present` route accepts only the numeric-age profile:
`pd-age-verification`, exactly one `age-credential` descriptor with `sd-jwt` / `$`,
the configured age-credential VCT, and exactly one application claim `age`, a finite
number at least 18. Other real profiles fail closed pending explicit eligibility
policies. Simulated scenarios remain on `/wallet-present`; they and `/present`
cannot satisfy an active authorization. A new authorization replaces the state
object so already-running legacy work cannot modify its status.

Issuer trust/signature, disclosure digest and holder-binding validation remain on
the existing cryptographic path. A signed age 12 explicitly passes that validator
but fails application eligibility. Successful application and status responses
return `eligible: true`; `disclosedClaims` is null and numeric age is not retained
in the session. The middleware still receives age during verification. This is
not issuer-signed boolean, mdoc or ZKP semantics (#97).

The wallet now sends its descriptor mapping instead of an empty descriptor list.
Resolver exceptions return a stable error without upstream diagnostic details.

## Verification

- `pnpm --filter verifier-backend exec vitest run src --testTimeout=30000`:
  12 files, 87 tests passed at the recorded revision.
- `pnpm exec turbo run build --filter=verifier-backend... --filter=@askmi/wallet-pwa...`:
  16 tasks successful (15 cached on the final run).
- Wallet suite: 16 files, 203 tests passed immediately before the commit;
  the final commit's only later code addition was backend status eligibility.
- Targeted ESLint: zero errors, five existing `no-explicit-any` warnings in app.ts.

Real-signature HTTP regressions cover underage, missing/wrong-type age, excess
signed name, wrong VCT, wrong submission definition, wrong audience, issuer
resolution failure, malformed input, replay, two independent sessions, signed
nonce mismatch, missing/wrong state, expiry, concurrent reservation, reset during
lookup, replacement authorization and simulated-route isolation. Existing backend
tests retain crypto/trust/revocation coverage. Tests use synthetic keys and a
synthetic trust-list fetch; this is not an external trust-list assurance.

## Remaining work

#170 and the pilot gate remain OPEN. The separate `@askmi/connect` API is not wired
into verifier-demo and its exact disclosure/profile enforcement needs its own
implementation and real-signature contract evidence. This slice changes no public
package API. No production deployment, complete browser E2E, official wallet
interoperability, durable replay protection or broader release approval is claimed.
