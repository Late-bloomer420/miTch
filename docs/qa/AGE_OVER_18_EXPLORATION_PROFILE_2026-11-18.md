# Age-over-18 exploration profile (Profile C) — 2026-11-18

**Scope:** `verifier-demo/backend`, route `POST /oid4vp-present`, new profile
`askmi-age-over-18-exploration-v0`. Step 3 of
[tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md](../tasks/AGE_VERIFIER_TEMPLATE_SCOPE_2026-11-17.md).
**Base revision:** `58d0af9` plus this change. Linux, Node `v22.23.5`, pnpm `9.15.9`, vitest `4.1.12`.

**This is not** an official EUDI or EU Age Verification profile, not a ZK proof, not
an unlinkability result and not a wallet interoperability result (#97 stays open).
The VCT `https://askmi.demo/vct/age-over-18-exploration` is repository-owned.

## Behaviour

- `GET /authorize?scenario=age-over-18-exploration` requests only `$.age_over_18`
  (`filter: { type: boolean, const: true }`) under definition
  `pd-askmi-age-over-18-exploration`. The verifier selects the profile from its own
  stored request, not from the wallet's submission.
- Accepted only after the existing issuer-signature, trust, status and KB-JWT checks:
  exactly one disclosed claim `age_over_18`, value the JSON boolean `true`, matching VCT,
  definition id and single `sd-jwt` descriptor at `$`.
- Application result (response and `/status`): `{ eligible: true, profile }`.
  `disclosedClaims` stays `null`. The numeric-age profile now also returns
  `profile: 'askmi-numeric-age-v0'` (additive field; app-internal, no package API change).
- Under this profile the verifier receives the boolean, not the age. The numeric-age
  profile is unchanged and still receives the age.

## Verification

- `npx vitest run src --testTimeout=30000` in `src/apps/verifier-demo/backend`:
  15 files, 122 tests passed.
- New `src/__tests__/age-over-18-profile.test.ts`: 18 tests with real P-256 issuer and
  holder signatures. Negatives: `false`, `"true"`, `1`, `null`, numeric `age` instead of
  the boolean, an additional claim, no claim, numeric-age VCT, cross-profile descriptor
  and definition, foreign issuer key, unresolvable issuer, wrong audience, wrong nonce,
  replay, stale authorization. Each rejected attempt is terminal.
- Mutation check: loosening the value check to `Boolean(v)` and the claim-set check to
  "contains the claim" made 3 tests fail (`"true"`, `1`, additional claim); restored.
- `tsc --noEmit` clean. ESLint on changed files: 0 errors, warnings `no-explicit-any` only.
- Prerequisite turbo build: `turbo run build --filter=verifier-backend^...`, 7 tasks.

## Not covered / open

- Disclosure strictness on this path depends on #288; on `master` an unreferenced
  disclosure is still dropped silently (#264). No test for that here.
- Trust list without anchor key is still accepted (#240/#276); status-list signature
  unverified (`API-05`); issuer JWKS `kid` selection open. Tests use a synthetic trust list.
- No issuer-mock issuance or wallet-pwa support for this profile; no browser E2E.
- No `decision_id` in the application result: the verifier has no decision record yet.
- Full `pnpm test` / `pnpm lint` across the monorepo not run; CI covers those.

## Addendum 2026-11-18 — expiry negatives (separate PR, base `d7f0e77`)

The sections above are unchanged. Linux, Node `v22.23.5`, pnpm `9.15.9`.

- `age-over-18-profile.test.ts` now has three more cases:
  - an expired credential (`exp` 60 s ago) is rejected with 403, and the attempt is
    terminal (a valid presentation afterwards is also rejected);
  - a credential whose `exp` is still in the future is accepted;
  - a credential **without** `exp` is accepted. This is a characterization of the
    documented gap (`exp` is optional), not a security PASS; see #293.
- Mutation check: disabling the `payload.exp < now` branch in `validateSDJWTVC`
  made exactly the expired-credential case fail; restored.
- `npx vitest run src --testTimeout=30000` in `src/apps/verifier-demo/backend`:
  15 files, 125 tests passed. `tsc --noEmit` clean; ESLint 0 errors.
- Still open: no maximum credential lifetime, revocation (#293).
