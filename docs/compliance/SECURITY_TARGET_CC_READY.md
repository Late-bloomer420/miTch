# miTch: Security Target (ST) - Security-Target Draft and Evaluation Mapping

> **Honest-scope note (2026-10-27, issue #235):** "CC-READY" in the filename and any certification-readiness wording in this draft are **not backed by an actual Common Criteria evaluation or an accredited CAB**. This is an internal draft engineering assessment (`docs/MATURITY_AND_LIMITATIONS.md`). No certification is claimed. See the [Regulatory Role Map](../04-legal/REGULATORY_ROLE_MAP.md).

**ID:** E-42
**Version:** 1.0 (2026-05-25)
**Classification:** Public (engineering assessment input)
**Target of Evaluation (TOE):** miTch EUDI Wallet Framework

## 1. Introduction
This draft retains the intended security objectives and component references for a possible Common Criteria assessment. It is not an accredited/accepted Security Target or an EAL readiness determination. The selected TOE, applicable Protection Profile and clause-level SFR mapping require evaluation work.

## 2. Security Objectives & Implementation

| Objective | Security Function (SF) | Implementation Module |
| :--- | :--- | :--- |
| **User Authentication** | WebAuthn Hardware Binding | `@askmi/shared-crypto/webauthn.ts` |
| **Data Integrity** | ECDSA (P-256) & COSE Sign1 | `@askmi/shared-crypto/signing.ts` |
| **Confidentiality** | AES-256-GCM Encryption | `@askmi/secure-storage` |
| **Privacy (Minimization)** | SD-JWT Selective Disclosure | `@askmi/shared-crypto/sd-jwt-vc.ts` |
| **Unlinkability** | Pairwise Ephemeral DIDs | `@askmi/shared-crypto/pairwise-did.ts` |
| **Revocation Check** | W3C StatusList2021 | `@askmi/revocation-statuslist` |

## 3. Mapping of engineering inputs to CC assurance classes

| CC Class | Requirement | miTch Evidence |
| :--- | :--- | :--- |
| **ADV (Development)** | Implementation Representation | Versioned source code, TypeScript types and specifications; implementation representation must be evaluated for the selected TOE. |
| **ATE (Tests)** | Internal Testing Inputs | Repository-controlled tests exercise named cases; they are not independent testing of all security functions. |
| **AVA (Vulnerability)** | Vulnerability Analysis | STRIDE-based Threat Model (`docs/specs/05_Threat_Model.md`). |
| **ALC (Lifecycle)** | Configuration Management | Git versioning and CI workflows; configuration/threshold enforcement requires its own evidence (EV-05). |

## 4. Operational Hardening
1. **Crypto-Shredding**: Owned-buffer zeroization via `SecureBuffer`; runtime copies and physical RAM erasure are outside that evidence (GAP-1).
2. **Identity Firewall**: Policy claim-filtering components; active SD-JWT request/scope integration remains #170.
3. **Fail-Closed Integration**: Failed cryptographic checks have named rejection paths; structural validation, eligibility and application authorization are separate contracts.

## 5. Conclusion
These mappings are useful engineering inputs. Formal readiness, independence of testing, isolation of the selected TOE, vulnerability assessment and certification are not established by this document. Preserve component evidence while recording #170–#173 and the existing residuals as separate scoped work.
