# miTch: Security Target (ST) - Certification Readiness Artefact

**ID:** E-42
**Version:** 1.0 (2026-05-25)
**Classification:** Public (Audit Readiness)
**Target of Evaluation (TOE):** miTch EUDI Wallet Framework

## 1. Introduction
This document serves as the formal **Security Target (ST)** according to Common Criteria (ISO/IEC 15408) for the miTch framework. It maps the technical implementation to the security functional requirements (SFR) defined in the EUDI Protection Profiles.

## 2. Security Objectives & Implementation

| Objective | Security Function (SF) | Implementation Module |
| :--- | :--- | :--- |
| **User Authentication** | WebAuthn Hardware Binding | `@askmi/shared-crypto/webauthn.ts` |
| **Data Integrity** | ECDSA (P-256) & COSE Sign1 | `@askmi/shared-crypto/signing.ts` |
| **Confidentiality** | AES-256-GCM Encryption | `@askmi/secure-storage` |
| **Privacy (Minimization)** | SD-JWT Selective Disclosure | `@askmi/shared-crypto/sd-jwt-vc.ts` |
| **Unlinkability** | Pairwise Ephemeral DIDs | `@askmi/shared-crypto/pairwise-did.ts` |
| **Revocation Check** | W3C StatusList2021 | `@askmi/revocation-statuslist` |

## 3. Mapping to CC Assurance Levels (EAL4+ Readiness)

| CC Class | Requirement | miTch Evidence |
| :--- | :--- | :--- |
| **ADV (Development)** | Implementation Representation | Full source code with 100% TS types and Spec documentation. |
| **ATE (Tests)** | Independent Testing | `pnpm turbo test` (>1660 tests) verifying all SFs. |
| **AVA (Vulnerability)** | Vulnerability Analysis | STRIDE-based Threat Model (`docs/specs/05_Threat_Model.md`). |
| **ALC (Lifecycle)** | Configuration Management | Git-based versioning with mandatory lint/test CI gates. |

## 4. Operational Hardening
1. **Crypto-Shredding**: Automatic zeroization of sensitive memory buffers via `SecureBuffer`.
2. **Identity Firewall**: Policy-enforced claim filtering to prevent over-disclosure.
3. **Fail-Closed Integration**: Any failed cryptographic check results in an immediate `DENY` decision.

## 5. Conclusion
miTch is technically prepared for a formal **EAL4+** evaluation. All security-relevant modules are isolated, documented, and fully tested.
