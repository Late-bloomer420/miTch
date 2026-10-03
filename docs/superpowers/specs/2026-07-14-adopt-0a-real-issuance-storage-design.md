# ADOPT-0a — Real SD-JWT VC Issuance + Storage

**Status:** Design — awaiting approval
**Date:** 2026-07-14
**Author:** Claude (Opus 4.8) with J F M / AskMI
**Parent design:** `docs/superpowers/specs/2026-07-14-adopt-0-real-credential-presentation-design.md` (ADOPT-0). This is its **first slice**; ADOPT-0b (present-from-stored + verify) follows.
**Track:** ADOPT: **ADOPT-0a (this)** → ADOPT-0b → ADOPT-1 (`@askmi/connect`) → ADOPT-2 (registry).
**Relates to:**
- `src/apps/issuer-mock/src/index.ts` (`/credential`, `signVC`, `ISSUER_DID = did:web:localhost%3A3005`, `/.well-known/jwks.json`)
- `src/packages/shared-crypto/src/sd-jwt-vc.ts` (`issueSDJWTVC`, `validateSDJWTVC`, `buildCNFClaim`, `extractCNFPublicKey`)
- `src/packages/shared-crypto/src/trust-list-resolver.ts` (`trustListResolver`)
- `src/apps/wallet-pwa/src/services/WalletService.ts` (`addIssuedCredential`, storage) + `src/apps/wallet-pwa/src/App.tsx` (`Get credential` flow, ~1023)
- Holder-binding / single-use pool: `shared-crypto/holder-binding.ts`, `wallet-pwa/credential-pool.ts` (#91/#92)

---

## 1. Context

Grounding ADOPT-0 revealed the credential is fabricated **at every layer**, not just at presentation:
- **issuer-mock** issues a plain **W3C VC-JWT** (`signVC`, `format: jwt_vc_json`) with a **placeholder holder** (`credentialSubject.id = did:key:zUnknownHolderForKeyBindingPoC`) — no SD-JWT selective-disclosure digests, no real holder `cnf` binding.
- the wallet **discards the signed credential** — `addIssuedCredential(id, subject, …)` calls `storage.save(id, subject, meta)`, persisting only the claim *values*, not the issuer-signed JWT.

So real selective disclosure + a real key-binding proof (ADOPT-0b) is impossible until issuance and storage produce and keep a genuine, holder-bound, issuer-signed **SD-JWT VC**. ADOPT-0a delivers exactly that foundation — and nothing more.

**Ephemerality framing (from ADOPT-0, unchanged):** the *issuer* key is persistent + trust-anchored (issuer-mock, resolvable via `trustListResolver`; a real issuer plugs in via the trust list, no code change). The *holder* key is a fresh, single-use-per-credential binding (unlinkability) — established here at issuance and stored with the credential.

## 2. Goal & Non-Goals

**Goal:** The wallet fetches and **stores a real, issuer-signed SD-JWT VC bound to a wallet-held holder key (`cnf`)** — such that `validateSDJWTVC(storedCredential, resolvedIssuerKey)` passes against the trust-list-resolved issuer key, and the matching holder private key is stored alongside for later key-binding.

**Non-Goals (explicit — ADOPT-0b or later):**
- **Presentation** — selective disclosure, KB-JWT creation, the OID4VP present path, and verifier F-14 wiring are ADOPT-0b. ADOPT-0a stops at "a genuine credential is stored."
- Removing the fabrication from `presentOID4VP` (0b) — the present path is untouched here.
- A real external issuer — issuer stays simulated (issuer-mock); only the persistent + trust-anchored + pluggable shape is delivered.
- New credential types beyond the pilot AgeCredential.

## 3. Architecture

### 3.1 issuer-mock issues a real SD-JWT VC bound to the wallet's holder key
- The OID4VCI `/credential` request already carries a `proof` field (currently ignored). ADOPT-0a: the wallet sends its **holder public key** (JWK) in `proof`; issuer-mock reads it and builds a **`cnf`** claim (`buildCNFClaim(holderPublicKey)`).
- issuer-mock issues via **`issueSDJWTVC(payload, issuerPrivateKey)`** (persistent issuer key) instead of `signVC` — producing a compact SD-JWT VC with `vct`, `iss = ISSUER_DID`, `cnf`, and the age claims, returned as the OID4VCI `credential` (format `vc+sd-jwt`). *(The disclosure-set handling follows `issueSDJWTVC`'s contract; if it returns the issuer JWT without appended disclosures, issuer-mock appends the `~disclosure~` segments per the sd-jwt-vc module.)*
- issuer-mock's issuer key stays resolvable via `did:web:localhost%3A3005` + `/.well-known/jwks.json`; **no issuer key is hardcoded into the wallet.**

### 3.2 Wallet: generate a holder key, request PoP, store the full credential
- Before fetching, the wallet generates a **fresh single-use holder keypair** (reuse `holder-binding.ts` / the credential-pool machinery, non-extractable P-256), and sends its public JWK as the `/credential` request `proof`.
- On response, the wallet stores the **full SD-JWT VC string** (issuer JWT + disclosures) **and the holder private key**, keyed to the credential — via an extended storage path (see §3.3). The extracted `subject` may remain as display metadata, but the **raw credential is now persisted** (it is no longer discarded).

### 3.3 Storage schema extension
- `addIssuedCredential` (or a focused new method `addSdJwtVc`) persists: the raw `sdJwtVc` string, the holder key reference, and the existing `StoredCredentialMetadata` (issuer, type, claims, single-use/pool fields). The stored payload changes from "subject only" to "the credential + its holder binding."
- `getCredentials()` / retrieval exposes the raw credential + holder key for ADOPT-0b to present from.

### 3.4 Trust anchoring (pluggable)
- A helper resolves the issuer key for `ISSUER_DID` via `trustListResolver` (`did:web` + JWKS). ADOPT-0a proves the **stored** credential validates against that resolved key — establishing the pluggable trust path a real issuer will use unchanged.

## 4. Data flow

wallet generates single-use holder keypair → `POST /credential` with `proof = holderPublicJwk` → issuer-mock `buildCNFClaim` + `issueSDJWTVC` (persistent issuer key) → SD-JWT VC (`vc+sd-jwt`, with `cnf`) → wallet stores raw SD-JWT VC + holder private key → `validateSDJWTVC(stored, trustListResolver-resolved issuer key)` passes; `extractCNFPublicKey` matches the stored holder public key.

## 5. Fail-closed

- No holder proof / holder key → issuer-mock does not issue (no anonymous cnf-less credential); wallet does not store.
- Issuance error or a credential whose issuer signature does not validate against the resolved key → **not stored** (no partial/invalid credential persisted).
- Storage retains the raw credential atomically with its holder key, or not at all.

## 6. Testing (TDD)

- **issuer-mock:** `POST /credential` with a holder JWK proof returns a `vc+sd-jwt` credential; `validateSDJWTVC(credential, issuerPublicKey)` → `ok: true`; `extractCNFPublicKey(payload)` equals the supplied holder key; a request without a holder proof is rejected (fail-closed).
- **wallet issuance:** the get-credential flow generates a single-use holder key, sends it, and stores the **raw SD-JWT VC + holder key**; a stored-credential round-trip returns the raw credential (not just claims).
- **trust resolution:** the stored credential validates against the `trustListResolver`-resolved issuer key; swapping the issuer key makes `validateSDJWTVC` fail (proves it is the real issuer signature).
- **unlinkability preserved:** two issued credentials have **distinct** holder `cnf`s (single-use); a regression test confirms the holder-binding/pool behavior is unchanged.
- Existing issuer-mock / wallet-issuance tests updated to the SD-JWT-VC shape.

## 7. Definition of Done

- [ ] issuer-mock issues a real **SD-JWT VC** (`issueSDJWTVC`, persistent issuer key) with a **`cnf`** derived from the wallet-supplied holder key; a proof-less request is rejected.
- [ ] The wallet generates a **single-use holder keypair**, requests PoP, and **stores the full SD-JWT VC + holder key** (the signed credential is no longer discarded).
- [ ] `validateSDJWTVC(storedCredential, trustListResolver-resolved key)` passes; `extractCNFPublicKey` matches the stored holder key; a swapped issuer key fails.
- [ ] Holder `cnf` is fresh/single-use per credential (unlinkability regression green).
- [ ] `pnpm build` + `pnpm test` + `pnpm lint` (0 errors) + `pnpm guard:rebrand` + `pnpm evidence` all green.
- [ ] The present path (`presentOID4VP`) is **untouched** — ADOPT-0a changes issuance + storage only.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| `issueSDJWTVC` disclosure/format details differ from assumption | The plan confirms `issueSDJWTVC`'s exact return contract and adapts issuer-mock to emit a `validateSDJWTVC`-parseable `vc+sd-jwt`; a test (`issue → validate`) is the gate. |
| Changing issuer-mock breaks the existing demo get-credential UI | The wallet get-credential flow is updated in lock-step; the credential card still renders (metadata retained), and the OID4VP present path is deliberately left on its current (fabricated) code until ADOPT-0b, so the live demo keeps working. |
| Storing a private holder key at rest | The holder key is stored in the existing encrypted `SecureStorage` (AES-256-GCM) like other key material; single-use minimizes exposure. |
| Scope creep into presentation | Present/verify are explicit non-goals; ADOPT-0a's DoD ends at "stored + validates," present path untouched. |

## 9. Successor

**ADOPT-0b** — present from the stored SD-JWT VC (selective disclosure of requested claims + real KB-JWT with the stored holder key), verifier F-14 `verifyCredentialSignatures` via `trustListResolver`, delete the `presentOID4VP` fabrication + `SCENARIO_CLAIMS` sourcing. Then ADOPT-1 (`@askmi/connect` kit) on a genuine end-to-end foundation.
