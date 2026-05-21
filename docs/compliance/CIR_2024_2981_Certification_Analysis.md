# CIR 2024/2981 — EUDI Wallet Certification Analysis

> Status: Research / Gap Analysis
> Reference: Commission Implementing Regulation (EU) 2024/2981
> Date: 2026-05-21

## 1. Core Objectives
CIR 2024/2981 establishes the certification framework for EUDI Wallets. It ensures that any wallet solution available in the EU meets a uniform bar for security, privacy, and interoperability.

## 2. Certification Requirements

| ID | Requirement | miTch Status | Notes |
|---|---|---|---|
| CERT-1 | Level of Assurance "High" (eIDAS LoA High) | 🟡 | Software-only PoC; hardware-backed keys (TEE/SE) required for production. |
| CERT-2 | Common Criteria (ISO/IEC 15408) Evaluation | 🔴 | Not yet prepared for formal CC evaluation. |
| CERT-3 | Conformity Assessment by Accredited CAB | 🔴 | External dependency. |
| CERT-4 | Security of Cryptographic Infrastructure (HSMs) | 🟡 | Mocked for development; requires production-grade HSM integration for Issuers. |
| CERT-5 | Privacy by Design & Data Minimization | ✅ | Core miTch architecture (SD-JWT, Crypto-Shredding). |
| CERT-6 | Interoperability (Cross-Border Recognition) | ✅ | Implemented via OID4VP/HAIP and SD-JWT VC. |

## 3. Gap Analysis

### A. Hardware Binding (T-31)
Production certification for LoA High requires that private keys are not extractable from the device. miTch currently uses `SoftwareKeyGuardian` which provides non-extractable keys via WebCrypto, but full certification requires TEE/Secure Element integration to prevent even OS-level access to key material.

### B. Formal Verification & Documentation
Certification requires a set of formal artifacts:
- Security Target (ST) document.
- Formal functional specifications (partially exist as `docs/specs/`).
- Vulnerability assessment and penetration testing reports (partially exist as `docs/ops/EVIDENCE_PACK_P0.md`).

### C. Dependency Analysis (Annex VI)
CIR 2024/2981 allows reusing existing certificates (e.g., for the Secure Element of a smartphone). miTch should be architected to rely on platform-native secure storage (iOS Secure Enclave / Android StrongBox) to simplify the certification path.

## 4. Next Steps for miTch
1.  **TEE Integration (T-31):** Move from software-only to hardware-backed key management.
2.  **Audit Hardening:** Ensure audit logs are signed in a way that meets CAB standards for non-repudiation.
3.  **Certification Roadmap:** Define a timeline for engaging with a Conformity Assessment Body (CAB).
