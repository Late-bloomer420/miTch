# ADOPT-0b — Real Credential Presentation (from the stored SD-JWT VC)

**Status:** Design — awaiting approval
**Date:** 2026-07-15
**Author:** Claude (Opus 4.8) with J F M / AskMI
**Parent design:** `docs/superpowers/specs/2026-07-14-adopt-0-real-credential-presentation-design.md` (ADOPT-0). This is its **second slice**; ADOPT-0a (issuance + storage) is merged (#135).
**Track:** ADOPT: ADOPT-0a ✅ → **ADOPT-0b (this)** → ADOPT-1 (`@askmi/connect`) → ADOPT-2 (registry).
**Relates to:**
- `src/apps/wallet-pwa/src/App.tsx` `presentOID4VP` (~820-939) — the fabrication core being replaced
- `WalletService.getSdJwtVc(id)` (ADOPT-0a) — the stored real credential + holder key
- `src/packages/shared-crypto/src/sd-jwt-vc.ts` (`createKeyBindingJWT`, `validateSDJWTVC`, `createSDJWTDisclosures`)
- `src/packages/oid4vp/src/demo-flow.ts` `buildSDJWTPresentation` (the *re-issuing* builder — NOT reused; see §3.1)
- `src/apps/verifier-demo/backend/src/app.ts` present routes (`/oid4vp-present` ~271) + `trustListResolver` (already imported/configured)
- `src/packages/oid4vp-verifier` F-14 `verifyAuthorizationResponse({ verifyCredentialSignatures, resolveIssuerKey })`

---

## 1. Context

ADOPT-0a made the wallet fetch + store a real, issuer-signed, holder-bound SD-JWT VC. But the present path still **fabricates**: `presentOID4VP` (App.tsx:833-856) generates a throwaway "issuer" keypair per presentation, reads hardcoded `SCENARIO_CLAIMS[scenario]`, and self-signs via `buildSDJWTPresentation` (which takes an `issuerPrivateKey` and *re-issues* the credential on the spot). The verifier therefore verifies a VP the wallet signed for itself — theater, not trust — and the real credential 0a stores is never used.

ADOPT-0b replaces **only the fabrication core** with real presentation from the stored credential, preserving the working UX (fetch request, policy eval, consent, POST, session-shred, audit). The demo keeps looking the same; the credential underneath becomes real.

## 2. Goal & Non-Goals

**Goal:** The wallet presents the **real stored SD-JWT VC** (ADOPT-0a) by **selectively disclosing exactly the requested claims** and attaching a **real KB-JWT** signed by the stored holder key — with the **issuer's original signature preserved** — and the verifier verifies that issuer signature against the **trust-list-resolved** issuer key. The ephemeral-issuer + `SCENARIO_CLAIMS` fabrication is removed from the present path.

**Non-Goals (explicit):**
- The `@askmi/connect` kit (ADOPT-1) and partner registry (ADOPT-2).
- A real external issuer (issuer stays simulated issuer-mock; only trust-list pluggability, already in place).
- New credential types beyond the pilot AgeCredential.
- The 0a-deferred *issuance-side* items (non-P-256→400 in issuer-mock, `x-correlation-id` on the fetch, `generateHolderBinding` extractable-key convergence) — those are issuance-surface, not this present slice; they remain separately tracked.

## 3. Architecture

### 3.1 New real presentation builder (no issuer key)
The existing `buildSDJWTPresentation` re-issues (takes `issuerPrivateKey`) — wrong for a pre-issued credential. Add a **new** builder in `@askmi/shared-crypto` (`sd-jwt-vc.ts`):
```ts
export async function buildSdJwtPresentation(
  sdJwtVc: string,                 // stored: issuerJwt~disc1~disc2~...~
  requestedClaimNames: string[],   // e.g. ['isOver18'] (or a predicate's underlying claim)
  holderPrivateKey: CryptoKey,
  opts: { aud: string; nonce: string }
): Promise<{ vpToken: string; disclosedClaims: Record<string, unknown> }>;
```
It: splits the stored credential into `issuerJwt` + disclosures; decodes each disclosure `[salt, name, value]`; **keeps only disclosures whose `name` is in `requestedClaimNames`** (drops the rest → selective disclosure); reconstructs `presented = issuerJwt~<selected disclosures>~`; computes the KB-JWT via `createKeyBindingJWT({ aud, nonce, sdJwtWithDisclosures: presented }, holderPrivateKey)`; returns `vpToken = presented + kbJwt` and the disclosed claim map. The **issuer JWT (and its signature) is untouched** — issuer authenticity is preserved.

### 3.2 Wallet: present from storage
`WalletService.presentStoredSdJwtVc(credentialId, requestedClaimNames, opts: { aud; nonce }): Promise<{ vpToken; disclosedClaims } | null>` — loads the stored credential + holder key via `getSdJwtVc` (0a), imports the holder private JWK, calls `buildSdJwtPresentation`. Returns `null` (fail-closed) when no stored credential matches.

### 3.3 App.tsx: swap the fabrication core, keep the flow
In `presentOID4VP`, **remove** the ephemeral issuer/holder keygen (833-840), the `SCENARIO_CLAIMS[scenario]` sourcing (842), and the `buildSDJWTPresentation` call; **replace** with a call to `presentStoredSdJwtVc` using the request's `nonce`/audience and the requested claim names derived from the presentation_definition. **Keep** everything else: `/notify-scan`, policy eval, consent UI, POST to `redirect_uri`, session cleanup/shred, audit. Fail-closed: if `presentStoredSdJwtVc` returns `null` (no stored credential), surface a clear "no matching credential — fetch one first" and present nothing (no `SCENARIO_CLAIMS` fallback).

### 3.4 Verifier: verify the real issuer signature
The present route the wallet POSTs to (`/oid4vp-present`) verifies the presented VP's **issuer signature** via F-14 `verifyAuthorizationResponse({ verifyCredentialSignatures: true, resolveIssuerKey, expectedAudience, expectedNonce })`, resolving the issuer key through the already-configured `trustListResolver` (issuer-mock `did:web` + JWKS). Issuer-sig or KB-JWT failure → reject.

## 4. Data flow

get-credential (0a: real SD-JWT VC + holder key stored) → verifier request → policy ALLOW → **present-from-storage** (load stored VC, select requested disclosures, KB-JWT with stored holder key; issuer JWT untouched) → POST vp_token → verifier resolves issuer key via `trustListResolver`, F-14 verifies **real issuer signature** + KB-JWT → verified. Session keys shredded after (unchanged).

## 5. Fail-closed

- No stored credential matching the request → present **nothing**; clear user message; **never** `SCENARIO_CLAIMS`/liquor-store fallback or a fabricated VP.
- A requested claim not present in the stored credential's disclosures → it is simply not disclosed (only genuinely-held claims), never invented.
- Issuer-signature or KB-JWT verification failure at the verifier → rejected, not reported valid.
- Holder key missing/unimportable → no presentation.

## 6. Testing (TDD)

- **`buildSdJwtPresentation`:** given a stored `issuerJwt~dob~over18~`, presenting `['isOver18']` yields `issuerJwt~<over18 disclosure>~<kbJwt>` — the `dob` disclosure is absent; the issuer JWT is byte-identical (signature preserved). *(jose `SignJWT` fails under jsdom — use the Task-5 WebCrypto KB-JWT approach / a Node-env test for the KB-JWT signing, matching the existing pattern.)*
- **`presentStoredSdJwtVc`:** loads a stored credential + holder key and returns a vpToken with only requested disclosures; **no stored credential → null** (fail-closed).
- **End-to-end issuer-signature:** a presented VP built from a real issuer-mock-signed stored credential verifies via F-14 against the `trustListResolver`-resolved key; swapping the issuer key → verification fails (proves the real issuer signature is carried, not a self-signed fabrication).
- **KB-JWT:** bound to the request nonce/aud → validates; wrong nonce → fails.
- **App present path:** the fabrication (ephemeral keygen + `SCENARIO_CLAIMS`) is gone; a present with no stored credential is fail-closed (no fabrication); the existing consent/shred flow still runs. Update the demo tests that asserted the fabricated path.

## 7. Definition of Done

- [ ] The pilot age-check completes with the **real stored** credential: `isOver18` disclosed, `dateOfBirth` withheld, verified against the **trust-resolved issuer key**; swapping the issuer key fails verification.
- [ ] Ephemeral-issuer keygen + `SCENARIO_CLAIMS` sourcing removed from `presentOID4VP`; a present with no stored credential fails closed (no fabrication, clear message).
- [ ] `buildSdJwtPresentation` preserves the issuer JWT (signature) and discloses only requested claims + a real KB-JWT.
- [ ] Verifier `/oid4vp-present` verifies the issuer signature via F-14 + `trustListResolver`.
- [ ] Holder/session ephemerality + crypto-shredding unchanged.
- [ ] `pnpm build` + `pnpm test` + `pnpm lint` (0 errors) + `pnpm guard:rebrand` + `pnpm evidence` all green.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Deleting the fabrication breaks the live demo | Wire the real path and prove it end-to-end (0a stored cred → present → verify) BEFORE removing the fabrication; re-point the age scenario to the stored credential; keep consent/POST/shred structure. |
| No stored credential at present time | Present-from-storage requires a fetched credential; fail-closed with a clear "fetch a credential first" message (the 0a Get-credential step is now a real precondition), not a silent fabrication. |
| jose `SignJWT` (KB-JWT) fails under wallet-pwa jsdom tests | Reuse the ADOPT-0a Task-5 WebCrypto KB-JWT test approach / Node-env test; production code path is unaffected. |
| Requested claims are predicates (e.g. age_over_18) not raw claim names | Map the presentation_definition fields to the credential's disclosure claim names (the pilot AgeCredential exposes `isOver18`); if a requested field has no matching disclosure, it is simply not disclosed (fail-closed, never invented). |
| Verifier F-14 needs issuer key resolution | `trustListResolver` is already imported + configured in the verifier backend; issuer-mock exposes `did:web` + JWKS. |

## 9. Successor

**ADOPT-1** (`@askmi/connect` kit) now sits on a genuine end-to-end presentation (spec drafted on the abandoned `feat/adopt-1-connect-kit` branch). **ADOPT-2** (partner registry + policy packs) follows. The 0a-deferred issuance-side cleanups remain separately tracked.
