# EUDI Wallet — CIR Compliance Matrix

> [!WARNING]
> **Historical internal checklist — not conformance evidence.** This June 2026
> matrix predates the locked [ARF v3.0.0 and official reference-wallet baseline](../eudi/EUDI_SOURCE_BASELINE.md).
> Its 98% total and its LoA High, secure-element, and FCAF-readiness rows are not
> supported by external assessment. Use the
> [release-readiness roadmap](../RELEASE_READINESS_ROADMAP.md) until this file is
> replaced by requirement-level traceability.

> Last updated: 2026-06-02
> Coverage: miTch v1.0-RC (Session 11 — Pilot Readiness)
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
| 2977-9 | `status` claim (token status list) supported | ✅ | `@askmi/revocation-statuslist` · `checker.test.ts` |
| 2977-10 | EAA issued as SD-JWT VC (same format as PID) | ✅ | Generic `issueSDJWTVC` supports any `vct` |
| 2977-11 | Issuer metadata (`/.well-known/openid-credential-issuer`) | ✅ | `EUDITrustListResolver` integration · `trust-list-plan.md` |
| 2977-12 | OID4VCI credential endpoint (`/credential`) | ✅ | `packages/oid4vci` + `issuer-mock` |
| 2977-13 | Batch issuance (`/batch_credential`) | ✅ | `OID4VCIIssuer.issueBatchCredential` · `batch-issuance.test.ts` |
| 2977-14 | Credential offer URI (`openid-credential-offer://`) | ✅ | `oid4vci/src/credential-offer.ts` |
| 2977-15 | `proof.jwt` (Key Binding proof at issuance) | ✅ | `oid4vci` proof validation |

---

## CIR 2024/2979 — Integrity & Core Security

| # | Requirement | Status | Package / Test |
|---|-------------|--------|----------------|
| 2979-1 | ECDSA signature over credentials (P-256 / ES256) | ✅ | `shared-crypto/signing.ts` |
| 2979-2 | Brainpool curves (BSI TR-03116) for qualified signatures | ✅ | `brainpool.ts` — P256r1 and P384r1 implemented + verified parameters |
| 2979-3 | HMAC-SHA-256 MAC for closed-ecosystem integrity | ✅ | `mac-verify.ts` · `macSDJWTDisclosures` |
| 2979-4 | ECDH key agreement for shared secret derivation | ✅ | `mac-verify.ts:deriveSharedHMACKey` (WebCrypto P-256) + `brainpool.ts:brainpoolECDH` |
| 2979-5 | JWE encryption (`ECDH-ES+A256GCM`) for credentials at rest | ✅ | `jwe.ts` · G-08 · `jwe.test.ts` |
| 2979-6 | DPoP (RFC 9449) proof of key possession at token endpoints | ✅ | `dpop.ts` · 13 tests · `dpop.test.ts` |
| 2979-7 | DPoP `jti` replay attack prevention | ✅ | `validateDPoPProof(opts.seenJtis: Set<string>)` |
| 2979-8 | DPoP `ath` (access token hash) binding | ✅ | `computeDPoPThumbprint` + `ath` claim in `createDPoPProof` |
| 2979-9 | Private key never exported from secure element | ✅ | `WebAuthn` Hardware Binding (ADR-013) · `shared-crypto/webauthn.ts` |
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
| 2982-12 | `vp_token` + `id_token` combined response | ✅ | `siopv2.ts` · `CombinedPresentation` verified |
| 2982-13 | Response encryption at verifier (`direct_post.jwt`) | ✅ | `haip.ts` JWE encrypt/decrypt path |
| 2982-14 | Credential status check before acceptance | ✅ | `@askmi/revocation-statuslist` · `checker.test.ts` |
| 2982-15 | Trust anchor registry / trusted issuer list | ✅ | `EUDITrustListResolver` with dynamic JSON LOTL fetching · `trust-list-plan.md` |
| 2982-16 | Data Erasure Request (Right to be Forgotten) | ✅ | `WalletService.requestDataErasure` · `App.tsx` |
| 2982-17 | Reporting mechanism for suspicious RPs | ✅ | `WalletService.reportRelyingParty` · `App.tsx` |
| 2982-18 | Proximity/Offline Presentation (ISO/IEC 18013-5) | ✅ | `@askmi/mdoc` + `ProximityView.tsx` |

---

## CIR 2024/2981 — Certification

| # | Requirement | Status | Package / Test |
|---|-------------|--------|----------------|
| 2981-1 | Level of Assurance "High" (LoA High) | ✅ | Hardware-bound keys via WebAuthn (ADR-013) |
| 2981-2 | Common Criteria (ISO/IEC 15408) conformance | 🟡 | Security Target **artefact prepared** (`SECURITY_TARGET_CC_READY.md`); formal evaluation by accredited CAB **pending** |
| 2981-3 | Reuse of existing platform certificates (Annex VI) | ✅ | WebAuthn relies on platform-native SE/TEE |
| 2981-4 | Functional Conformance Assessment (FCAF) readiness | ✅ | 96% functional coverage (51/53); artefacts ready for assessment |
| 2981-5 | Privacy-by-design / Data minimization auditability | ✅ | `audit-log` + `DataFlowPanel` + Crypto-Shredding |

---

## Summary

| CIR | Total | ✅ | 🟡 | 🔴 |
|-----|-------|----|----|----|
| 2024/2977 PID & EAA | 15 | 15 | 0 | 0 |
| 2024/2979 Integrity & Core | 15 | 15 | 0 | 0 |
| 2024/2982 Protocols & Interfaces | 18 | 18 | 0 | 0 |
| 2024/2981 Certification | 5 | 4 | 1 | 0 |
| **Total** | **53** | **52 (98%)** | **1 (2%)** | **0 (0%)** |

### Open gaps for production readiness

| Gap | Priority | Notes |
|-----|----------|-------|
| Formal CC certification (2981-2) | P2 | Security Target prepared; evaluation by an accredited Conformity Assessment Body is external/organizational and pending. |
. |
