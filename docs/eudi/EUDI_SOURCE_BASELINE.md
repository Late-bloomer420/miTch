# EUDI official-source baseline

**Locked:** 2026-08-26  
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
| [Android wallet](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/releases/tag/Wallet/Demo_Version%3D2026.08.41-Demo_Build%3D41) | 2026.08.41-Demo, build 41 | First wallet interop anchor |
| [iOS wallet](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui/releases/tag/Wallet/Demo_2026.08.41-Demo_Build%3D41) | 2026.08.41-Demo, build 41 | Second wallet interop anchor |
| [Android core](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/releases/tag/v0.30.2) | v0.30.2 | Protocol/credential reference |
| [iOS core](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/releases/tag/v0.40.8) | v0.40.8 | Protocol/credential reference |
| [Official issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/releases/tag/v0.9.8) | v0.9.8 | Issuance anchor |
| [Official verifier](https://github.com/eu-digital-identity-wallet/eudi-web-verifier/releases/tag/v0.12.0) | v0.12.0 | Presentation comparison anchor |
| [FCAF](https://github.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/releases/tag/v0.0.10) | v0.0.10 | Functional test baseline |

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
