# CIR 2024/2981 — EUDI Wallet Certification Analysis

> Status: Research / Gap Analysis
> Reference: Commission Implementing Regulation (EU) 2024/2981
> Date: 2026-05-25

## 1. Core Objectives
CIR 2024/2981 establishes the certification framework for EUDI Wallets. It ensures that any wallet solution available in the EU meets a uniform bar for security, privacy, and interoperability.

## 2. Certification Requirements

| ID | Requirement | miTch Status | Notes |
|---|---|---|---|
| CERT-1 | Level of Assurance "High" (eIDAS LoA High) | ✅ | Hardware-bound identity keys via WebAuthn (ADR-013). |
| CERT-2 | Common Criteria (ISO/IEC 15408) Evaluation | 🟡 | Draft Security Target artefact exists; formal evaluation has not started. |
| CERT-3 | Conformity Assessment by Accredited CAB | 🔴 | External dependency. |
| CERT-4 | Security of Cryptographic Infrastructure (HSMs) | 🟡 | Mocked for development; requires production-grade HSM integration for Issuers. |
| CERT-5 | Privacy by Design & Data Minimization | ✅ | Core miTch architecture (SD-JWT, Crypto-Shredding). |
| CERT-6 | Interoperability (Cross-Border Recognition) | ✅ | Implemented via OID4VP/HAIP and SD-JWT VC. |

## 3. Implementation State

### A. Hardware Binding (ADR-013)
Production certification for LoA High requires that private keys are not extractable from the device. miTch implements this via platform-native WebAuthn (Passkeys/FIDO2). This ensures that identity and presentation keys are bound to the device's Secure Element (SE) or Trusted Execution Environment (TEE), meeting the non-extractability requirement of eIDAS LoA High.

### B. Formal Verification & Documentation
Certification requires a set of formal artifacts:
- Security Target (ST) draft.
- Formal functional specifications (exist as `docs/specs/`).
- Vulnerability assessment and penetration testing reports (`docs/ops/EVIDENCE_PACK_P0.md`).

### C. Dependency Analysis (Annex VI)
miTch relies on platform-native secure storage (iOS Secure Enclave / Android StrongBox) via the WebAuthn API to simplify the certification path by reusing existing platform-level certificates.

## 4. Next Steps for miTch
1.  **Trust List Integration:** Complete signed official LOTL/TSL validation instead of relying on pilot JSON trust-list fixtures.
2.  **Audit Hardening:** Ensure audit logs are signed in a way that meets CAB standards for non-repudiation.
3.  **Certification Roadmap:** Define a timeline for engaging with a Conformity Assessment Body (CAB).
