# EUDI Wallet — CIR Compliance Matrix

> Last updated: 2026-03-06
> Coverage: miTch v0.8 (Session 8 — EUDI/eIDAS 2.0 Compliance Sprint)
>
> Legend: ✅ Implemented | 🟡 Partial | 🔴 Missing | ➖ Not applicable

---

## CIR 2024/2977 — PID & EAA (Person Identification Data + Electronic Attestation of Attributes)

| # | Requirement | Status | Package / Test |
|---|-------------|--------|----------------|
| 2977-1 | PID issued as SD-JWT VC (`vct` claim identifies credential type) | ✅ | `shared-crypto/sd-jwt-vc.ts` · `issueSDJWTVC` |
| 2977-2 | `iss` MUST be a URI identifying the issuing authority | ✅ | `sd-jwt-vc.ts:validateSDJWTVC` · `isURI()` guard |
| 2977-3 | `sub` present when PID bound to a subject | ✅ | Passed through `SDJWTVCPayload.sub` |
| 2977-4 | `exp` / `nbf` validity window enforced | ✅ | Manual exp/nbf validation (jose clockTolerance bypass) |
| 2977-5 | `cnf.jwk` Key Binding: holder public key embedded | ✅ | `buildCNFClaim` / `extractCNFPublicKey` |
| 2977-6 | Key Binding JWT (`kb+jwt`) required for PID presentation | ✅ | `createKeyBindingJWT` / `validateKeyBindingJWT` |
| 2977-7 | `_sd_alg: sha-256` mandatory for selective disclosure | ✅ | `issueSDJWTVC` sets `_sd_alg` unconditionally |
| 2977-8 | SD-JWT VC `typ` header MUST be `vc+sd-jwt` | ✅ | `sd-jwt-vc.ts` sign options `{ typ: 'vc+sd-jwt' }` |
| 2977-9 | `status` claim (token status list) supported | 🟡 | `SDJWTVCPayload.status` field present; status endpoint not yet deployed |
| 2977-10 | EAA issued as SD-JWT VC (same format as PID) | ✅ | Generic `issueSDJWTVC` supports any `vct` |
| 2977-11 | Issuer metadata (`/.well-known/openid-credential-issuer`) | 🟡 | `mock-issuer` serves metadata; not yet registered in EUDI Trust List |
| 2977-12 | OID4VCI credential endpoint (`/credential`) | ✅ | `packages/oid4vci` + `issuer-mock` |
| 2977-13 | Batch issuance (`/batch_credential`) | 🔴 | Not implemented — deferred post-MVP |
| 2977-14 | Credential offer URI (`openid-credential-offer://`) | ✅ | `oid4vci/src/credential-offer.ts` |
| 2977-15 | `proof.jwt` (Key Binding proof at issuance) | ✅ | `oid4vci` proof validation |

---

## CIR 2024/2979 — Integrity & Core Security

| # | Requirement | Status | Package / Test |
|---|-------------|--------|----------------|
| 2979-1 | ECDSA signature over credentials (P-256 / ES256) | ✅ | `shared-crypto/signing.ts` |
| 2979-2 | Brainpool curves (BSI TR-03116) for qualified signatures | 🟡 | `brainpool.ts` — P256r1 production-ready; P384r1 stub pending BSI param verification |
| 2979-3 | HMAC-SHA-256 MAC for closed-ecosystem integrity | ✅ | `mac-verify.ts` · `macSDJWTDisclosures` |
| 2979-4 | ECDH key agreement for shared secret derivation | ✅ | `mac-verify.ts:deriveSharedHMACKey` (WebCrypto P-256) + `brainpool.ts:brainpoolECDH` |
| 2979-5 | JWE encryption (`ECDH-ES+A256GCM`) for credentials at rest | ✅ | `jwe.ts` · G-08 · `jwe.test.ts` |
| 2979-6 | DPoP (RFC 9449) proof of key possession at token endpoints | ✅ | `dpop.ts` · 13 tests · `dpop.test.ts` |
| 2979-7 | DPoP `jti` replay attack prevention | ✅ | `validateDPoPProof(opts.seenJtis: Set<string>)` |
| 2979-8 | DPoP `ath` (access token hash) binding | ✅ | `computeDPoPThumbprint` + `ath` claim in `createDPoPProof` |
| 2979-9 | Private key never exported from secure element | 🟡 | `SoftwareKeyGuardian` (non-extractable ECDH keys); HSM/TEE integration deferred |
| 2979-10 | Key separation (signing vs encryption vs key-binding keys) | ✅ | G-07 — `keys.ts` with separate key purpose enum |
| 2979-11 | Secure buffer zeroization after use | ✅ | `secure-buffer.ts` — `SecureBuffer.wipe()` |
| 2979-12 | Nonce freshness enforcement (presentation) | ✅ | `nonce-store.ts` — TTL-based, single-use |
| 2979-13 | OAuth 2.0 Attestation-Based Client Auth | ✅ | `client-attestation.ts` · `attestation+pop+jwt` chain |
| 2979-14 | Client attestation `jti` replay prevention | ✅ | `validateClientAttestationChain(seenJtis)` |
| 2979-15 | Verifier Attestation JWT (`verifier_attestation` client_id_scheme) | ✅ | `haip.ts:issueVerifierAttestation` / `validateVerifierAttestation` |

---

## CIR 2024/2982 — Protocols & Interfaces

| # | Requirement | Status | Package / Test |
|---|-------------|--------|----------------|
| 2982-1 | OID4VP (OpenID for Verifiable Presentations) | ✅ | `oid4vp` package — core flow |
| 2982-2 | Presentation Definition (DIF PE v2) | ✅ | `oid4vp/src/presentation-definition.ts` |
| 2982-3 | SIOPv2 (`id_token`, `sub_jwk`) | ✅ | `siopv2.ts` · 15 tests |
| 2982-4 | Pairwise pseudonymous `sub` (per-verifier) | ✅ | `computePairwiseSub()` — SHA-256(clientId:holderDID) |
| 2982-5 | Nonce and state binding in SIOPv2 | ✅ | `createSIOPv2Response` + `validateSIOPv2IDToken` checks |
| 2982-6 | HAIP compliance (`direct_post.jwt` response mode) | ✅ | `haip.ts:validateHAIPRequest` enforces `response_mode` |
| 2982-7 | HAIP `limit_disclosure=required` enforcement | ✅ | `buildHAIPPresentationDefinition` sets per-field |
| 2982-8 | HAIP JWE response (`ECDH-ES+A256GCM`) | ✅ | `encryptDirectPostResponse` / `decryptDirectPostResponse` |
| 2982-9 | DID-based subject identifier support | ✅ | `did.ts` + `did-verification.ts` |
| 2982-10 | Pairwise ephemeral DIDs (Spec 111 — unlinkability) | ✅ | `pairwise-did.ts` · Phase 1 committed |
| 2982-11 | SD-JWT disclosure selective release | ✅ | Holder-side selective disclosure via SD-JWT `_sd` arrays |
| 2982-12 | `vp_token` + `id_token` combined response | 🟡 | `siopv2.ts` parses combined request scope; full combined response path not wired in wallet-pwa |
| 2982-13 | Response encryption at verifier (`direct_post.jwt`) | ✅ | `haip.ts` JWE encrypt/decrypt path |
| 2982-14 | Credential status check before acceptance | 🟡 | `sd-jwt-vc.ts` reads `status` claim; live revocation list fetch not yet implemented |
| 2982-15 | Trust anchor registry / trusted issuer list | 🟡 | `haip.ts` checks `trustedVerifiers` set; full EUDI Trust List integration pending |

---

## Summary

| CIR | Total | ✅ | 🟡 | 🔴 |
|-----|-------|----|----|----|
| 2024/2977 PID & EAA | 15 | 13 | 2 | 1 |
| 2024/2979 Integrity & Core | 15 | 13 | 2 | 0 |
| 2024/2982 Protocols & Interfaces | 15 | 11 | 4 | 0 |
| **Total** | **45** | **37 (82%)** | **8 (18%)** | **1 (2%)** |

### Open gaps for production readiness

| Gap | Priority | Notes |
|-----|----------|-------|
| brainpoolP384r1 verified parameters | P1 | BSI TR-03116 certified parameter set required; HSM preferred |
| Batch issuance (`/batch_credential`) | P2 | OID4VCI §7 — deferred post-MVP |
| Live status list revocation fetch | P1 | Token Status List RFC — endpoint integration |
| EUDI Trust List registration | P1 | Qualified issuer/verifier registration via eIDAS node |
| Combined `vp_token`+`id_token` wallet flow | P2 | Wallet-PWA wiring needed |
