# EUDI official-source baseline

> **Provenance — 2026-10-14:** this dated source/version registry is preserved from PR #169 head
> `4d4cc604337a88738ec51d9f1ce448d5330e0f56` (locked 12 October).
> The 26 October delta below refreshes official release observations; the original provenance above remains historical. No implementation or interop run is implied.
> Revalidate official sources and exact SHAs before starting interop; no source-watch entry closes a gate.
> Keep released UI/core coordinates separate and all upstream security requirements as open AskMI work until active code plus tests prove them.

**Locked:** 2026-10-26  
**Purpose:** External source/version registry for the AskMI release roadmap  
**Change rule:** Reconcile any newer official release before carrying evidence forward

## What the "real EU ID wallet" is

The European Commission reference implementation is published across the [EU Digital Identity Wallet GitHub organization](https://github.com/eu-digital-identity-wallet). It is not one monolithic original repository.

The primary user-facing reference wallets are the [Android wallet](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui) and [iOS wallet](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui). Their reusable engines are [Android wallet core](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core) and [iOS wallet kit](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit).

The EC describes this as a modular, ARF-driven reference implementation with limited scope. It is development/reference software, not proof that AskMI is production-ready or certified.

## Locked versions

| Component | Locked release | AskMI use |
|---|---|---|
| [ARF](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases/tag/v3.0.0) | v3.0.0, 2026-07-23 | Architecture/requirement baseline |
| [Android wallet](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases/tag/Wallet/Demo_Version%3D2026.10.43-Demo_Build%3D43) | 2026.10.43-Demo, build 43 (`4b295477f69351c1015ae253006bf240dd02d8ef`) | First wallet interop anchor |
| [iOS wallet](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/releases/tag/Wallet/Demo_2026.10.43-Demo_Build%3D43) | 2026.10.43-Demo, build 43 (`92ac8f7080ae104f4e3615c48c5cd9e40aada33f`) | Second wallet interop anchor; integrates Wallet Kit v0.52.1 |
| [Android core](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/releases/tag/v0.31.0) | v0.31.0 (`efcd3a48248f75c3767df06c972c5e2361ba1be9`) | Protocol/credential and trust reference |
| [iOS core](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.56.6) | v0.56.6 (`8a3b97da681c8d74056709d9b42eaf6523450eb7`) | Independent core comparison anchor; not released build 43 integration |
| [Official web issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/releases/tag/v0.10.0) | v0.10.0 (`4a9233215c12d720ac0ca52c36bfeeb0651c1514`) | General issuance and JWT registration-certificate metadata anchor |
| [PID issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/releases/tag/v0.11.2) | v0.11.2 (`bdd5ea0bb9d6de685ecfb3c8ad8db06e6a168647`) | PID schema and certificate-header anchor |
| [Verifier UI](https://github.com/eu-digital-identity-wallet/eudi-web-verifier/releases/tag/v0.13.0) | v0.13.0 (`763efa70e5b00eb6bccddc7166b97bd1bca36e8d`) | Presentation UX/comparison anchor |
| [Verifier endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint/releases/tag/v0.12.0) | v0.12.0 (`19537e72a633b25c94b7450bf582760f52ab2cc9`) | Protocol/configuration comparison anchor |
| [FCAF](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/releases/tag/v0.0.10) | v0.0.10 | Functional test baseline |
| [RP registration](https://github.com/eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py/releases/tag/v0.2.2) | v0.2.2 | WRP access/registration certificate and intended-use comparison anchor |

"Latest" must never appear in evidence without a resolved tag and commit SHA.

## Additional official sources

| Concern | Official source |
|---|---|
| Reference scope | [EC reference implementation profile](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md) |
| Feature status | [Feature map](https://github.com/eu-digital-identity-wallet/eudi-docs-site/blob/main/docs/reference-implementation/feature-map.md) |
| Repository catalog | [Official repository list](https://github.com/eu-digital-identity-wallet/eudi-docs-site/blob/main/docs/reference-implementation/repositories-list.md) |
| Attestation profiles | [Rulebooks Catalog](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog) |
| Standards gaps | [Standards and Technical Specifications](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications) |
| Verifier endpoint | [OID4VP verifier endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt) |
| PID issuer | [PID issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer) |
| Proximity verifier | [Multiplatform verifier](https://github.com/eu-digital-identity-wallet/eudi-app-multiplatform-verifier-ui) |
| RP registration | [RP registration service](https://github.com/eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py) |
| Trusted lists | [Trusted-list manager](https://github.com/eu-digital-identity-wallet/eudi-srv-web-trustedlist-manager-py) |
| End-to-end tests | [EUDI testing application](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application) |
| Legal implementation | [EC wallet implementing regulations](https://digital-strategy.ec.europa.eu/en/library/implementing-regulation-european-digital-identity-wallets) |

## Deltas that directly affect AskMI

ARF v3.0.0 includes current relying-party services/registration, trust-anchor retrieval using ETSI TS 119 612 Trusted Lists and ETSI TS 119 602 Lists of Trusted Entities, wallet-to-wallet updates, and FCAF.

The official stack uses current OpenID4VP/OpenID4VCI profiles, DCQL, mso_mdoc and SD-JWT VC, and native mobile security capabilities. AskMI's Presentation Exchange flow, custom/draft issuance boundary, JSON DID trust list, and browser WebAuthn path are useful prototypes—not equivalence proof.

## Upstream delta — 2026-10-26

Compared with the 19 October watch and the default-branch registry at AskMI `208154e9a436d3844f85e4fa02a048140622f121`. These are requirements and evidence gaps, not reproduced AskMI exploits or completed implementation.

| Classification | Official change | AskMI consequence / affected gate / required action |
|---|---|---|
| Interoperability/evidence invalidation | [iOS Wallet Kit v0.56.6](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.56.6), released 25 October, includes [authorization-server metadata caching](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/517). | Wave 1/3 issuance and deferred-flow evidence must record cache lifetime/reset and server URL. Test same-server reuse, different-server isolation, failed-discovery retry, changed metadata and issuance/offer/update reset. Do not carry old discovery evidence forward without these cases. High before rerun. |
| AskMI implementation gap | [Token authorization details](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/506) now select an identifier-based credential request when identifiers are returned; a missing identifier for the requested configuration fails. | `oid4vci` / Wave 1: test identifier-based and configuration-based paths, token/configuration binding, missing/wrong identifiers and multiple configurations. High before official issuer integration. |
| AskMI implementation gap; interoperability/evidence invalidation | [EncryptionSupportConfig](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/510) exposes credential request/response encryption; [iOS UI main](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/pull/601) configures support with WalletKit v0.56.5. | Wave 1/3: explicitly record encryption policy and algorithms; test supported/required/unavailable combinations, wrong keys, malformed ciphertext and downgrade rejection. UI main is not a new released wallet; build 43 still integrates v0.52.1. |
| Trust/security risk | [SD-JWT issuer-key selection](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/514) supports absent `kid`, selects an unambiguous metadata key and rejects encryption keys. | `shared-crypto` and issuer adapter / Wave 2: add missing/unknown `kid`, multiple signing keys, encryption-only key and foreign embedded-JWK negatives. Header key material must not establish trust independently of trusted issuer metadata. High before SD-JWT interop. |
| Interoperability/evidence invalidation | [v0.56.5 change](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/516) removes `readerCertIssuerValid` and updates OpenID4VP dependency. | Wave 3 adapter must use `readerAuthenticationStatus`, deny not-evaluated/untrusted states for the pilot, and test exhaustive status handling. Preserve v0.56.0 enforce-only policy. |
| Roadmap decision | [PID issuer v0.11.2](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/releases/tag/v0.11.2), released 19 October, promotes optional `iss`/`iat` Type Metadata declarations from watch to a tagged coordinate. | Wave 2 PID fixtures: optional metadata declarations must not weaken actual credential issuer/signature/time checks. Re-lock to `bdd5ea0bb9d6de685ecfb3c8ad8db06e6a168647`; this is not removal of JWT validation requirements. |
| Watch; trust/security risk | Untagged [verifier change 6ae7c576](https://github.com/eu-digital-identity-wallet/eudi-web-verifier/commit/6ae7c576e3fea15fa703d8669164c7bb4604560c) requests whole `place_of_birth` plus locality/country/region. | `oid4vp` / policy minimisation / Waves 1–3: test parent-object versus leaf authorization, duplicate paths, missing fields and rejection of excess disclosure. Never copy the broader request into a narrow purpose policy automatically. Keep released verifier UI v0.13.0. |

**Carry-forward correction:** [v0.56.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.56.0) adds `jarSigningAlg` (RS256 default; configurable). Wave 3 must record the verifier's exact request-signing algorithm and test supported, mismatched and unsupported algorithms without fallback/downgrade. This addresses the omitted requirement identified in [PR #179 review](https://github.com/Late-bloomer420/miTch/pull/179#discussion_r4311521689).

**Coverage:** latest release lists were checked for all eleven locked components. Default-branch commits since 19 October were checked for ARF, standards/specifications, rulebooks catalog, FCAF, docs site, trusted-list manager, RP registration, Android wallet/core, iOS wallet and verifier UI/endpoint. No new decision was found in the unchanged document/trust/Android tracks; verifier dependency maintenance does not itself prove an AskMI vulnerability or justify advancing its released anchor. FCAF stays v0.0.10; submitted tests remain distinct from released conformance.

**Implementation boundary:** the inspected AskMI `src/packages/oid4vci/src/index.ts` still implements a custom mock issuance contract; `src/packages/oid4vp/src/presentation-request.ts` parses Presentation Exchange. These files do not establish the new official-profile behavior. Existing internal tests and the scoped Connect progress in BACKLOG remain valid for their stated scope; official-wallet parity remains unproven. No gate or date changes.

## Upstream delta — 2026-10-19

[iOS Wallet Kit v0.56.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.56.0) supersedes v0.54.8 as the tagged iOS-core anchor, through intermediate [v0.55.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.55.0).

- **Roadmap decision and trust/security risk:** v0.56.0 introduces a separate `readerTrustPolicy`. The default `.enforce` rejects an untrusted OpenID4VP reader certificate chain; an explicit `.warning` policy permits an otherwise valid signed X.509 request to proceed as `authenticatedWithUntrustedCertificate`. Signature verification, chain parsing and leaf/signing-certificate matching still apply. AskMI's pilot profile remains enforce-only: treat the warning status as untrusted/denied, never show a trusted-reader badge, and test that it cannot be conflated with `authenticated`. If a development comparison enables warning mode, record it as a non-gating deviation. See [PR #507](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/507).
- **Interoperability/evidence invalidation and AskMI implementation gap:** [v0.55.0 / PR #505](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/505) adds opt-in per-key proof signing for key attestation without exporting private keys. iOS issuance evidence must record whether key proofs are required and prove ordered per-key signatures, nonce forwarding, unlock/authentication context and rejection of missing, reordered or invalid proofs.
- **No pilot-scope expansion:** v0.55.0 also adds CSC QES transaction-data handling. QES remains outside the frozen AskMI pilot. Keep the default accepted transaction-data set empty and reject unsupported/unconfigured types; do not convert upstream support into an AskMI QES claim.

[Official web issuer v0.10.0](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/releases/tag/v0.10.0) supersedes v0.9.8. It can publish a JWT registration certificate in credential-issuer metadata under `issuer_info` with format `registration_cert` from an optional configured file ([commit `4a9233215`](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/commit/4a9233215c12d720ac0ca52c36bfeeb0651c1514)). This is an **AskMI implementation gap and trust/security risk**: the issuer adapter must parse, signature/trust/status/validity-check and bind the registration certificate to the expected issuer and registered scope; missing, malformed, expired, revoked, wrong-issuer and wrong-scope cases must fail closed. Metadata presence alone is not trust evidence.

The official [FCAF roadmap update](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/commit/f42e3b2d8e4efad311439e632904ea59cbeb455c) is a **roadmap decision**. Submitted baseline test cases and ISO/IEC TS 18013-6 ICS references are usable for pilot feedback but are not a released baseline; a versioned beta follows public-feedback processing and the release candidate is targeted for Q1 2027. Keep FCAF v0.0.10 as the locked reproducible coordinate until deliberately re-locked, record any submitted-branch cases separately, and do not interpret current test execution as certification or RC conformance.

**Watch, not a new release lock:** PID issuer main [commit `e7ed02e6d`](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/commit/e7ed02e6d05d9e2c99952d84e7b09aa595e31893) marks `iss` and `iat` non-mandatory in PID v1.4 SD-JWT VC Type Metadata. The tagged anchor remains v0.11.1. Add future-schema fixtures for absent metadata declarations without weakening actual credential issuer/signature/time validation. The independently released [Topic AA SCA discussion paper v0.8](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases/tag/Topic_AA_rr_paper_v0.8) remains a watch item; ARF stays v3.0.0 and payments/SCA expansion stays outside the frozen pilot.

**No impact to current released anchors:** Android/iOS wallet UIs remain build 43; Android core remains v0.31.0; PID issuer remains v0.11.1; verifier UI/endpoint remain v0.13.0/v0.12.0; FCAF remains v0.0.10; and RP registration remains v0.2.2. iOS UI main now consumes Wallet Kit v0.56.0, but build 43 still integrates v0.52.1 and must not be relabelled.

No readiness gate closes and no target date moves from this delta.

## Upstream delta — 2026-10-12

[iOS Wallet Kit v0.54.8](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.54.8) supersedes v0.54.5 as the tagged iOS-core anchor. The intermediate [v0.54.6](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.54.6), [v0.54.7](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.54.7) and v0.54.8 changes materially affect issuance, status and presentation evidence:

- **Trust/security risk and interoperability/evidence invalidation:** [PR #500](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/500) tracks reader authentication independently from certificate display/registration warnings, rejects X.509 presentation requests without successful trusted-certificate validation, resets state between requests and blocks responses after failed or incomplete decoding. AskMI has no exact reader-authentication status contract or regression evidence. Before carrying iOS presentation evidence forward, test missing trust evaluation, untrusted/invalid certificate and signature, malformed decode, stale state after failure, overlapping receives and response attempts without an authenticated request identity.
- **Trust/security risk and AskMI implementation gap:** [v0.54.7 commit `af99be4`](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/commit/af99be409707d8321f17e4de43ba3bd1e5d6b4ee) rejects status-list JWTs with a missing algorithm, `none`, invalid values or symmetric HS algorithms before certificate-trust validation. AskMI has general signature and algorithm denial codes but no status-token-specific allowlist evidence. Add missing/`none`/HS/invalid/unsupported status-JWT negatives and require an asymmetric allowed algorithm plus trusted signer chain.
- **Interoperability/evidence invalidation:** [v0.54.7 commit `60bfde8`](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/commit/60bfde835ee70b52c005e183193444a86a21d13b) creates JWT and key-attestation proofs with the resolved client ID from the active issuer configuration rather than the credential-issuer identifier. Add a test where those values differ and prove the JWT `iss`/client binding uses the resolved client ID for attested and explicitly allowed plain-proof modes.
- **Roadmap decision / interoperability:** [PR #497](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/497) makes the device-signature algorithm configurable for BLE and OpenID4VP mdoc signatures, with ES256 as the default. Record the selected device algorithm in every mdoc interop artifact; reject unsupported or unnegotiated changes rather than relying on a library default.

**Watch, not a new release lock:** Android wallet main fixes an open revoked-document details screen after the revocation worker fires ([commit `3572043`](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/commit/3572043b035ac306aedfd0fb618092f360cec92a)) and resumes OpenID4VCI authorization only for the initiating issuer ([commit `2c56231`](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/commit/2c56231f987216f4c0be8ad8edc3fa19ee98b87b)). These are material future regression cases, but build 43 remains the released Android UI anchor; do not relabel main-branch evidence as build 43.

**No impact to current locked gates:** ARF remains v3.0.0; Android core remains v0.31.0; mobile UI releases remain build 43; PID issuer remains v0.11.1; verifier UI/endpoint remain v0.13.0/v0.12.0; FCAF remains v0.0.10; and RP registration remains v0.2.2. Trust Validator main moved through a v0.3.1-alpha version bump with UI/tooling changes, but the roadmap continues to treat alpha releases as non-gating references.

No readiness gate closes and no target date moves from this delta.

## Upstream delta — 2026-10-05

The released mobile anchors moved to [Android build 43](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases/tag/Wallet/Demo_Version%3D2026.10.43-Demo_Build%3D43) and [iOS build 43](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/releases/tag/Wallet/Demo_2026.10.43-Demo_Build%3D43). Build-42 evidence is now historical. The iOS UI integrates Wallet Kit v0.52.1, while the independently tagged core is v0.54.5; these remain separate evidence coordinates. TrustMark and Privacy Dashboard UI are reference features, not certification evidence.

- **Interoperability/evidence invalidation and trust/security risk:** [Android core v0.31.0](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/releases/tag/v0.31.0) supersedes v0.30.2. Its [release comparison](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/compare/v0.30.2...v0.31.0) includes reader-authentication fail-closed fixes, issuer-trust and invalid-signature fixes, OpenID4VP transaction data for SD-JWT VC and mdoc, TS10 transaction logs, distinct rejection events, multiple credential identifiers and explicit ETSI/Standard issuance-proof profiles. Do not carry v0.30.2 trust evidence forward. Rerun reader-auth, missing-chain, invalid-signature, rejected-presentation, multi-credential and proof-profile negatives on v0.31.0; proof-profile selection must be explicit and cannot silently downgrade.
- **Interoperability/evidence invalidation and roadmap decision:** [iOS Wallet Kit v0.54.5](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.54.5) supersedes v0.53.5. The [comparison](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/compare/v0.53.5...v0.54.5) adds TrustMark handling, transaction-log changes, explicit ETSI revocation configuration, OpenID4VP/OID4VCI updates and nested WRPRC `srv_description` values. Record revocation configuration and prove fail-closed status behavior; test nested description parsing and metadata-resolution failures. The official [TrustMark documentation](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/blob/v0.54.5/Sources/EudiWalletKit/EudiWalletKit.docc/TrustMark.md) states that display information does not independently verify wallet certification, so AskMI must never convert TrustMark display metadata into a certification claim.
- **AskMI implementation gap and trust/security risk:** [PID issuer v0.11.1](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/releases/tag/v0.11.1) tags the previously watched Rulebook alignment and SD-JWT certificate-header work. [PR #651](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/pull/651) removes the separate house-number claim, adds administrative-validity dates and permits derived/optional expiry; [PR #652](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/pull/652) adds `x5u`, `x5t#S256` and a signing-certificate endpoint. Update PID schemas and fixtures now. Treat administrative validity separately from credential `iat`/`exp`; if `x5u` is accepted, require allowlisted HTTPS, bounded retrieval, trusted-chain validation and thumbprint matching.
- **Interoperability/evidence invalidation:** [Verifier UI v0.13.0](https://github.com/eu-digital-identity-wallet/eudi-web-verifier/releases/tag/v0.13.0) tags the DC API/ITB flow, PID claim removal and JSONPath security fix previously tracked on main. Digital Credentials API remains outside the frozen pilot unless scope is reopened. Separately, [verifier endpoint v0.12.0](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint/releases/tag/v0.12.0) changes the status-check configuration key, reports SD-JWT VC validation outcomes, binds wallet `iss` to JAR `aud`, distinguishes response-return failures and adds authorization-request `iat`. Keep UI and endpoint evidence separate and test the renamed configuration, audience binding, `iat` and typed failures.
- **Watch / trust-security risk:** [Trust Validator v0.3.0-alpha](https://github.com/eu-digital-identity-wallet/eudi-srv-trust-validator/releases/tag/v0.3.0-alpha) adds certificate-profile fixes, CRL-then-OCSP revocation, cache controls and aggregated trust-source errors through the official ETSI library. Use it to shape Wave 2 revocation, cache-expiry, outage and rollback tests, but do not make an alpha release a pilot gate anchor.
- **No locked-baseline impact / watch:** ARF remains v3.0.0. Merged discussion papers on [strong customer authentication](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/pull/763), [pseudonyms](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/pull/769) and [qualified electronic signatures](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/pull/767) do not alter that tag. Payments/QES remain outside the frozen pilot; pseudonyms remain a longer-term watch item. FCAF v0.0.10 and RP registration v0.2.2 remain unchanged.

No readiness gate closes and no target date moves from this delta.

## Upstream delta — 2026-09-28

[iOS Wallet Kit v0.53.5](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.5) supersedes v0.53.0 as the tagged iOS-core anchor. The official [v0.53.0...v0.53.5 comparison](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/compare/v0.53.0...v0.53.5) produces four material AskMI consequences:

- **Trust/security risk and AskMI implementation gap:** [v0.53.3](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.3) rejects issued SD-JWT credentials whose protected header uses `alg: none`. AskMI already verifies issuer signatures, but no explicit unsigned/`none` negative evidence was found. Add a positive algorithm allowlist and missing/`none`/unexpected-algorithm tests; do not treat parser or library defaults as gate evidence.
- **Interoperability/evidence invalidation:** [v0.53.4](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.4) validates the RFC 9207 `iss` authorization-response parameter during credential issuance and preserves issuer-metadata failures rather than flattening them into offer-resolution errors. AskMI's OID4VCI evidence must bind the authorization response to the expected issuer when advertised and retain distinguishable discovery, metadata, offer, authorization and token error classes.
- **AskMI implementation gap:** [v0.53.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.2) keeps one issuance transaction identifier across token-refresh retries, while [v0.53.4](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.4) and [v0.53.5](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.5) add WRPRC `srv_description`, background-update and unsuccessful-presentation logging. AskMI currently has no exact `transactionIdentifier` or `reasonOfNoncompletion` contract. Extend the value-free audit schema and tests before carrying v0.53 evidence forward.
- **Trust/security policy decision:** [v0.53.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.2) exposes an OpenID4VP error-dispatch policy whose compatibility default can notify unauthenticated clients. AskMI's deny-biased reference profile must dispatch protocol errors only after verifier authentication, and must test that invalid unauthenticated requests receive no callback containing request or wallet state.

**Watch / roadmap decision, not a new release lock:** the RP-registration service remains tagged at [v0.2.2](https://github.com/eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py/releases/tag/v0.2.2), but its main-branch [Launchpad 2026 guide](https://github.com/eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py/blob/main/launchpad2026.md) pins TS5 v1.3, TS6 v1.1, ETSI TS 119 411-8 v1.1.1 and ETSI TS 119 475 v1.2.1, and requires a WRP access certificate before a WRP registration certificate for the documented legal-person/no-intermediary flow. Wave 2 must capture those exact contract revisions, sequence and secret-handling evidence; intermediary behavior remains a separately tested path. Do not treat untagged main as v0.2.2 evidence.

The released iOS wallet UI remains build 42, and the other locked rulebook, trust, conformance, issuer, verifier, Android wallet/core and registration releases are unchanged. No gate or date advances from this delta.

## Upstream delta — 2026-09-21

[iOS Wallet Kit v0.53.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.53.0) supersedes v0.51.0 as the tagged iOS-core anchor. The release contains two material compatibility changes:

- **Trust/security risk and AskMI implementation gap:** [v0.52.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.52.0) adds an issuer-specific `allowPlainJwtProof` switch. It defaults to `false` and therefore keeps HAIP-style attested proofs; enabling it accepts plain JWT proofs without key attestation using ES256, ES384, or ES512. AskMI must keep attested proof as the default, allow plain proof only by explicit issuer/profile policy, record the selected proof mode and algorithm, and test downgrade rejection. Public-client fallback and plain credential proof are separate decisions and must not be collapsed into one evidence field.
- **Interoperability/evidence invalidation:** [v0.53.0 transaction logging](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/blob/v0.53.0/Sources/EudiWalletKit/EudiWalletKit.docc/GetStarted.md) persists a request as `NotCompleted` before credential selection, updates the same record by transaction identifier, and marks completion only after successful response delivery. Cancellation, failure, rejection and interruption remain non-completed; requested-claim logs cover the union of DCQL alternatives, while presented-claim logs contain disclosed paths and no claim values. AskMI evidence must prove these state transitions, idempotent update semantics and value-free audit storage; a redirect returned with an `access_denied` rejection is not a successful disclosure.

The released iOS wallet UI remains [build 42](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/releases/tag/Wallet/Demo_2026.09.42-Demo_Build%3D42). Its main branch has only moved to Wallet Kit 0.52.1, so build-42 UI evidence must not be relabelled as v0.53.0 evidence.

**Watch/no current locked-release impact:** the official verifier merged [release-branch commit `5975c099`](https://github.com/eu-digital-identity-wallet/eudi-web-verifier/commit/5975c099ec9342144e7c0f324d42d9c946f16e69), adding an ITB-initialised Digital Credentials API flow and removing `resident_house_number`. No v0.13.0 release exists and the package still identifies itself as `0.12.1-SNAPSHOT`; the locked verifier therefore remains v0.12.0. Digital Credentials API remains outside the frozen pilot scope. If main-branch ITB evidence is used, record this exact commit separately and do not substitute it for tagged v0.12.0 evidence.

No readiness gate closes or target date moves from these changes.

## Upstream delta — 2026-09-14

The official mobile interop anchors moved to [Android wallet build 42](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases/tag/Wallet/Demo_Version%3D2026.09.42-Demo_Build%3D42) and [iOS wallet build 42](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/releases/tag/Wallet/Demo_2026.09.42-Demo_Build%3D42). The iOS build integrates [Wallet Kit v0.51.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.51.0), reconciles document registrations after storage changes and immediately after issuance, and adds SwiftData as an alternative storage backend.

AskMI consequences:

- Replace build 41 in future official-wallet matrices; existing build-41 evidence is historical and cannot establish build-42 behavior.
- For iOS, record the storage backend/app-group configuration and prove post-issuance registration reconciliation before using a credential. Exercise stale/removed registration and storage-reset cases.
- Preserve the v0.50 migration rules (iOS 17+, delete/reissue old stored documents and bound authentication context) when testing v0.51.0.

Android build 42 [requires strong biometrics for cryptographic authentication and stops retrying terminal errors or duplicating prompts](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/commit/3e75b4202170e78af7c2409d209fa6e5041adce7). Android evidence must record authenticator class and test strong-capable success, weak-only failure, cancellation, terminal error, and duplicate-prompt prevention. This constrains the official-wallet evidence environment; it does not make the AskMI browser harness a WSCA/WSCD equivalent.

Two unreleased PID-issuer main-branch changes are material watch items; the locked issuer tag remains v0.11.0 until a release:

- The [latest PID Rulebook alignment](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/commit/b16b9833f5ae7c9d4185147d2619a224f4f79672) removes separate house-number and `trust_anchor` claims, makes expiry optional, and derives issuance/expiry from administrative-validity dates. Wave 2 PID schemas and tests must reject removed fields, accept missing expiry, and distinguish credential issuance/expiry from administrative validity.
- The issuer now emits [`x5u` and `x5t#S256` in SD-JWT VC headers](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/commit/13cffc06c60235ab764c0cfab1f33a640098f8b6). AskMI's active SD-JWT verifier resolves keys by issuer and has no explicit certificate-header policy. Before official issuer interop, define whether `x5u` is accepted; if accepted, use allowlisted HTTPS retrieval with size/time limits, validate the certificate chain and require the SHA-256 thumbprint to match. Never follow an untrusted credential-supplied URL blindly.

No readiness gate closes from these upstream changes.

## Upstream delta — 2026-09-07

[iOS Wallet Kit v0.50.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.50.0) supersedes v0.40.9 as the latest tagged core release. It reuses a shared local-authentication context during one issuance or presentation operation, changes `KeyAccessControl` from an option set to an enum, requires deletion/reissuance of existing stored documents because of metadata changes, and raises the minimum deployment target to iOS 17.

AskMI consequences:

- Treat the released iOS wallet UI and wallet-core tag as separate evidence coordinates; do not claim that the still-locked UI build 41 was tested with core v0.50.0.
- Run the iOS matrix on iOS 17 or newer and record device/OS/core/UI revisions.
- Treat a v0.40.9 → v0.50.0 upgrade as a destructive test-fixture migration: delete and reissue credentials, and never carry stored-document evidence across the boundary.
- Record prompt count and authentication-context lifetime for issuance and presentation, including a negative test proving authentication state is not reused across independent transactions.

[RP registration v0.2.2](https://github.com/eu-digital-identity-wallet/eudi-srv-web-relyingparty-registration-py/releases/tag/v0.2.2) adds access- and registration-certificate history, changes credential/provided-attestation `meta` from a string to an object, and requires an intermediary identifier when the intended-use certificate must contain intermediary information.

AskMI currently has no WRPRC or intended-use implementation in the active codebase. Before Wave 2 can exit, the RP-registration adapter and evidence must cover object-shaped metadata, deterministic selection and validation of the current certificate from history, intermediary/on-behalf-of identity, intended-use scope, and stale/revoked/status-list failures. The [official iOS presenter-log change](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/commit/bc92d38a12e0bf47173940ec00aaedc913ec840e) further confirms that the connecting certificate subject can differ from the registered WRP name; AskMI audit records must preserve both identities rather than collapse them.

No gate or target date moves from these source changes.

## Upstream delta — 2026-08-31

[iOS Wallet Kit v0.40.9](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.40.9) supersedes the prior v0.40.8 lock and changes two OpenID4VCI-relevant behaviors:

- When authorization-server metadata omits `client_attestation_pop_signing_alg_values_supported`, the kit can create a public client using an explicitly configured `clientId` instead of failing. AskMI must test attested-client and public-client modes, or explicitly scope one out, and must preserve the selected mode in revision-bound evidence. See [official commit 0a859d2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/commit/0a859d227acb9443c968d49ad9e12ba0a5218dc8).
- Credential-offer resolution is cached by offer URI. AskMI issuer paths must use unique, immutable, short-lived/single-use offer URIs and test repeated resolution, expiry, and replay; changing offer content behind an unchanged URI is not a supported assumption. See [official commit cc4b80e](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/commit/cc4b80eac8e94f93e89efb9317baff039086e212).

This delta invalidates only future or existing iOS OpenID4VCI evidence that does not record the client mode or credential-offer URI/cache behavior. It does not close or otherwise change a readiness gate.

## AskMI role boundary

### In scope

- verifier/RP policy mediation and request minimisation;
- trusted issuer/RP/registration evaluation;
- auditable fail-closed decisions;
- OpenID4VP/OpenID4VCI and credential-format interoperability;
- adapters for the official EC wallet stack; and
- reference harnesses for repeatable tests.

### Not established

- certified EUDI Wallet Solution or LoA High;
- certified WSCA/WSCD;
- national PID Provider or CAB status;
- legal compliance, production security, or EC endorsement.

## Evidence required per interop run

- official repo, tag, commit; AskMI commit;
- protocol/profile and rulebook version;
- device/OS/browser/deployment configuration;
- issuer/wallet/verifier/trust/RP registration configuration;
- happy path and failure cases;
- machine-readable artifacts and summary;
- deviations, skipped tests, unresolved defects, reviewer/date.

## Update process

1. Check current tagged ARF and component releases.
2. Review official feature-map/rulebook changes.
3. Classify compatibility, work, evidence invalidation, or out-of-scope impact.
4. Update this file, roadmap, traceability, and QA evidence.
5. Rerun invalidated evidence and record the decision.
