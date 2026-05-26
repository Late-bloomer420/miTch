# miTch: Security Target Draft - Certification Readiness Artefact

**ID:** E-42
**Version:** 1.0 (2026-05-25)
**Classification:** Public (Audit Readiness)
**Target of Evaluation (TOE):** miTch EUDI Wallet Framework

## 1. Introduction
This document is a draft **Security Target (ST)** readiness artefact for a future Common Criteria (ISO/IEC 15408) evaluation of the miTch framework. It maps the technical implementation to candidate security functional requirements and is not a certification result.

## 2. Security Objectives & Implementation

| Objective | Security Function (SF) | Implementation Module |
| :--- | :--- | :--- |
| **User Authentication** | WebAuthn Hardware Binding | `@mitch/shared-crypto/webauthn.ts` |
| **Data Integrity** | ECDSA (P-256) & COSE Sign1 | `@mitch/shared-crypto/signing.ts` |
| **Confidentiality** | AES-256-GCM Encryption | `@mitch/secure-storage` |
| **Privacy (Minimization)** | SD-JWT Selective Disclosure | `@mitch/shared-crypto/sd-jwt-vc.ts` |
| **Unlinkability** | Pairwise Ephemeral DIDs | `@mitch/shared-crypto/pairwise-did.ts` |
| **Revocation Check** | W3C StatusList2021 | `@mitch/revocation-statuslist` |

## 3. Mapping to CC Assurance Levels (EAL4+ Readiness)

| CC Class | Requirement | miTch Evidence |
| :--- | :--- | :--- |
| **ADV (Development)** | Implementation Representation | Full source code with TypeScript types and specification documentation. |
| **ATE (Tests)** | Independent Testing | Monorepo Vitest/Turbo suite plus targeted checks for security functions; exact counts should be taken from the current CI run. |
| **AVA (Vulnerability)** | Vulnerability Analysis | STRIDE-based Threat Model (`docs/specs/05_Threat_Model.md`). |
| **ALC (Lifecycle)** | Configuration Management | Git-based versioning with mandatory lint/test CI gates. |

## 4. Operational Hardening
1. **Crypto-Shredding**: Automatic zeroization of sensitive memory buffers via `SecureBuffer`.
2. **Identity Firewall**: Policy-enforced claim filtering to prevent over-disclosure.
3. **Fail-Closed Integration**: Any failed cryptographic check results in an immediate `DENY` decision.

## 5. Conclusion
miTch has a credible starting point for a formal **EAL4+** preparation track. Before claiming formal evaluation readiness, the project still needs signed official trust-list validation, issuer-side proof-of-possession validation, CAB engagement, and an externally reviewed evidence package.
