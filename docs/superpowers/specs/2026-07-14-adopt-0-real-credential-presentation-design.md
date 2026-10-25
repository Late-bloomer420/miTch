# ADOPT-0 — Real Credential Presentation

**Status:** Design — awaiting approval
**Date:** 2026-07-14
**Author:** Claude (Opus 4.8) with J F M / AskMI
**Track:** ADOPT (re-ordered). ADOPT-0 (this — real presentation) → ADOPT-1 (`@askmi/connect` kit) → ADOPT-2 (partner registry + policy packs).
**Relates to:**
- `src/apps/wallet-pwa/src/App.tsx` `presentOID4VP` (the demo fabrication being replaced)
- `src/apps/issuer-mock/src/index.ts` (`signVC`, `ISSUER_DID = did:web:localhost%3A3005`, `/.well-known/jwks.json`) — the persistent, resolvable (simulated) issuer
- `src/packages/shared-crypto/src/trust-list-resolver.ts` (`EUDITrustListResolver`, `trustListResolver`) — the pluggable issuer-trust abstraction
- `src/packages/shared-crypto/src/sd-jwt-vc.ts` (`validateSDJWTVC`, `createKeyBindingJWT`, disclosures)
- `src/packages/oid4vp-verifier` F-14 (`verifyAuthorizationResponse` with `verifyCredentialSignatures` + `resolveIssuerKey`)

---

## 1. Context

The pilot demo *looks* end-to-end but the wallet's OID4VP present path is **fabricated**. `presentOID4VP` (`App.tsx:820-876`):
- generates a **throwaway "issuer" keypair per presentation** (`App.tsx:837-840`) and self-signs the SD-JWT — the wallet impersonates the issuer;
- uses **hardcoded `SCENARIO_CLAIMS[scenario]`** claim values (`App.tsx:842`), defaulting to liquor-store;
- generates a **throwaway holder key** unrelated to any stored credential.

So F-14's real signature verification, when enabled, would be verifying a VP the wallet just signed for itself — not a credential issued by a trusted issuer. This blocks any genuine third-party adoption (ADOPT-1/-2), which is why the track was re-ordered to do this first.

**Ephemerality — the precise framing (settled with user):**
- **Ephemeral *issuer* keys are the bug.** ADOPT-0 removes per-presentation issuer keygen. The credential is signed by a **persistent** issuer whose key is **resolvable via the trust list**.
- **Ephemeral *holder / session* keys are a privacy *feature* and are preserved.** Pairwise-ephemeral DIDs, single-use holder bindings (credential pool, #91/#92), and crypto-shredded session keys (W-05) give unlinkability ("Alle sind AskMI"). Making them persistent would regress privacy.
- **Simulated-but-pluggable issuer (settled with user):** the issuer is **simulated by issuer-mock** for now (no real issuer partner yet), but as a *proper persistent, trust-anchored* issuer (`did:web` + JWKS + trust list) — architected so a **real issuer (Austria ID / an eIDAS national eID) plugs in by adding a trust-anchor / `did:web` entry, with no present-path code change**.

## 2. Goal & Non-Goals

**Goal:** The wallet presents a **real, issuer-signed, stored** credential by **selectively disclosing exactly the verifier's requested claims** plus a **genuine key-binding proof**, verified against a **trust-list-resolved issuer key** — replacing the `SCENARIO_CLAIMS` + ephemeral-issuer fabrication.

**Non-Goals (explicit):**
- The integration kit (ADOPT-1) and partner registry (ADOPT-2).
- A *real external* issuer integration — issuer stays **simulated (issuer-mock)**; ADOPT-0 only ensures the *architecture is ready* to plug one in via the trust list.
- New credential *types* or wallet UI redesign — the pilot age/health credentials suffice.
- Changing the unlinkability model — pairwise DIDs, single-use holder bindings, and session-key crypto-shredding are **preserved as-is**.

## 3. Architecture

### 3.1 Persistent issuer, resolved via the trust list (not hardcoded)
- issuer-mock already exposes the real-issuer interface: `ISSUER_DID = did:web:localhost%3A3005`, `/.well-known/jwks.json`, `/.well-known/openid-credential-issuer`, and signs VCs with a **persistent** key (`signVC`).
- The wallet **fetches a real credential once** (the existing "Get credential (OID4VCI)" flow, `App.tsx:1023` → `POST http://localhost:3005/credential`) and **stores** it (issuer-signed SD-JWT VC).
- The verifier resolves the issuer key through **`trustListResolver` (EUDITrustListResolver)** / the issuer's `did:web` + JWKS — **never** a key hardcoded to issuer-mock. A real issuer becomes a new trust-list entry; the present/verify code is unchanged. This is the "ready to plug a real one in" requirement.

### 3.2 Present-from-storage (the core change)
Rewrite the OID4VP present path so that, on policy ALLOW:
1. **Select a stored credential** that satisfies the request (issuer-signed SD-JWT VC from storage; for unlinkability, a single-use member from the credential pool where applicable).
2. **Selectively disclose** only the claims the verifier's `presentation_definition` requests — from the credential's real disclosures — **preserving the issuer's original signature over the SD-JWT**.
3. Attach a **real KB-JWT** signed by the **holder key bound into that credential's `cnf` at issuance** (fresh-per-credential / single-use for unlinkability — *not* a present-time throwaway), bound to the verifier's `nonce` + `audience`.
4. POST the resulting VP; the verifier (F-14) verifies the **issuer signature against the trust-list-resolved key** + the KB-JWT.

Delete the ephemeral-issuer keygen and `SCENARIO_CLAIMS` sourcing from the present path.

### 3.3 Pieces reused (not rebuilt)
`WalletService.getCredentials()` + storage; `shared-crypto/sd-jwt-vc` (`validateSDJWTVC`, `createKeyBindingJWT`, disclosures); the OID4VP SD-JWT presentation builder (sourced from the **stored** credential + its real issuer JWT, not fabricated claims); `trustListResolver` for issuer-key resolution; issuer-mock `signVC` + `/.well-known/jwks.json`. *(Exact reuse-vs-extend of `buildSDJWTPresentation` / `WalletService.generatePresentation` is confirmed in the plan; the primitives are present.)*

## 4. Data flow

Get-credential (issuer-mock `signVC` → issuer-signed SD-JWT VC → stored) → verifier `/authorize` (presentation_definition) → policy ALLOW → **present-from-storage** (load stored VC, selective-disclose requested claims, real KB-JWT bound to nonce/aud) → verifier resolves issuer key via `trustListResolver` and verifies the **real issuer signature** (F-14 `verifyCredentialSignatures`) + KB-JWT → verified. Session/transport keys crypto-shredded after.

## 5. Fail-closed

- **No stored credential satisfies the request → present nothing**, surface a clear "no matching credential." **Never** fall back to `SCENARIO_CLAIMS` / liquor-store / a fabricated VC.
- Issuer-signature or KB-JWT verification failure → no presentation reported as success.
- Requested claims the holder doesn't have → disclosed set is only what is genuinely held (or DENY); never invented.
- Issuer key not resolvable via the trust list → fail-closed (untrusted issuer), never present against an unverifiable issuer.

## 6. Testing (TDD)

- **Selective disclosure:** presenting a stored VC for a request discloses exactly the requested subset; withheld claims are absent from the VP.
- **Real issuer signature end-to-end:** the presented VP verifies via F-14 `verifyAuthorizationResponse({ verifyCredentialSignatures: true, resolveIssuerKey: <trust-list resolver> })` against the issuer-mock key — and **fails** if the issuer key is swapped (proves it is the real signature, not self-signed).
- **KB-JWT:** bound to the request nonce/audience → verifies; wrong nonce → fails.
- **No-match fail-closed:** a request for a credential not held → no presentation, clear reason, no fabrication.
- **Pluggable issuer:** issuer-key resolution goes through `trustListResolver`; a test asserts the present/verify path takes the issuer identity from the credential + trust list (so a second trust-anchored issuer would work without code change).
- **Unlinkability preserved:** a regression test confirms pairwise-DID / single-use-holder-binding behavior is unchanged (holder key differs per verifier; session key shredded).
- Existing demo tests that assert the fabricated path are updated to the real path; fabrication is removed.

## 7. Definition of Done

- [ ] The pilot age-check flow completes with a **real issuer-mock-issued, stored** credential: age selectively disclosed, others withheld, verified against the **trust-list-resolved issuer key** (not an ephemeral one).
- [ ] Ephemeral **issuer** keygen and `SCENARIO_CLAIMS` sourcing are removed from the OID4VP present path; a request with no matching stored credential fails closed (no fabrication).
- [ ] Issuer-key resolution flows through `trustListResolver` (pluggable) — no issuer key hardcoded into the present/verify path.
- [ ] Holder/session ephemerality + crypto-shredding + pairwise-DID unlinkability are **unchanged** (regression test green).
- [ ] `pnpm build` + `pnpm test` + `pnpm lint` (0 errors) + `pnpm guard:rebrand` + `pnpm evidence` all green.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Removing the fabrication breaks the live demo flow | The real path is wired incrementally and proven end-to-end (get→store→present→verify) before the fabrication is deleted; demo scenarios re-pointed to a real stored credential. |
| The wallet has no stored credential at present time | Present-from-storage requires a fetched credential; the "Get credential" step becomes a real precondition (fail-closed with a clear prompt if absent), not a silent fabrication. |
| Issuer-key resolution accidentally hardcodes issuer-mock | DoD + a test require resolution via `trustListResolver`; issuer identity comes from the credential, not a constant. |
| Weakening unlinkability while making the holder key "real" | The holder key is the credential's issuance-bound `cnf` (single-use per credential), not a reused stable key; a regression test asserts pairwise unlinkability + shredding are intact. |
| Scope creep into a real external issuer integration | Explicit non-goal: issuer stays simulated (issuer-mock); only the *pluggability* is delivered. |

## 9. Successor

**ADOPT-1** (`@askmi/connect` kit) now sits on a genuine presentation (spec drafted, deferred behind this). **ADOPT-2** (partner registry + policy packs) follows. A real external issuer (Austria ID / eIDAS national eID) plugs into the trust list when a partner joins — no ADOPT-0 rework, by design.
