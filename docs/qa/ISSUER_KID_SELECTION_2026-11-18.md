# Issuer key selection by `kid` — 2026-11-18

**Scope:** `verifier-demo/backend` issuer-key resolution for `POST /oid4vp-present`
(`resolveTrustedIssuerKey`), plus `issuer-mock` issuance header. Remaining `kid` item of
#240; step 4 (part 1) of
[tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md](../tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md).
**Base revision:** `58d0af9` plus this change. Linux, Node `v22.23.5`, pnpm `9.15.9`, vitest `4.1.12`.

## Before

`resolveTrustedIssuerKey` imported `jwks.keys[0]` regardless of the credential.
`issueSDJWTVC` set no `kid`; issuer-mock published `kid: 'key-1'` but never used it.
Signature verification still ran, so this was not a signature bypass: with several keys
the verifier checked against an arbitrary one (wrong denies, no clean rotation), and it
would import whatever the first JWKS entry was, including private or non-signing keys.

## After

- `selectIssuerJwk` (`backend/src/issuer-jwks.ts`): candidates are public `EC`/`P-256`
  keys with `x`,`y`, `use` absent or `sig`, `alg` absent or `ES256`; any `d` is rejected.
  With a header `kid`, exactly one candidate must match. Without one, exactly one
  candidate must exist. Otherwise `null` → `untrusted_or_unresolvable_issuer` (403).
- `/oid4vp-present` and the Connect route (`/askmi/connect/.../presentation`) both pass the
  credential's protected-header `kid` to the resolver. `@askmi/connect`'s
  `issuerKeyResolver` gains an optional second parameter `kid` (additive).
- `issueSDJWTVC(payload, key, options?)`: new optional `{ kid }`; existing callers unchanged.
  issuer-mock sets `kid: 'key-1'` on issued SD-JWT VCs.

## Verification

- New `issuer-kid-selection.test.ts`: 12 unit cases for `selectIssuerJwk` /
  `protectedHeaderKid` and 4 HTTP cases with two real JWKS keys (second key selected by
  `kid`; mismatched `kid`; unknown `kid`; no `kid` with ambiguous JWKS), plus 3 Connect
  route cases for the same rule (follow-up `kid` finding on #292). Removing the `kid`
  forwarding on the Connect path made the Connect second-key case fail; restored.
  After merging master: verifier-backend 16 files / 141 tests; connect 5 / 66.
- Mutation check: reverting to `jwks.keys[0]` made 3 of the HTTP cases fail, including
  acceptance under an unknown `kid`; restored.
- Suites: verifier-backend 15 files / 120 tests; shared-crypto 32 / 312; oid4vp 8 / 94;
  issuer-mock 2 / 9 (after building `@askmi/mdoc`, whose missing build output had failed
  the suite identically on the unchanged base). `tsc --noEmit` clean in all four.
- ESLint on changed files: 0 errors.

## Not covered / open

- Trust list without anchor key (#240/#276) and status-list signature (`API-05`) unchanged.
- Credentials without a `status` claim skip revocation entirely
  (`oid4vp/src/demo-flow.ts:366`); issuer-mock issues none. Tracked as a decision in the
  template scope, not changed here.
- No issuer JWKS caching, rotation policy or `x5c`/certificate chain handling.
