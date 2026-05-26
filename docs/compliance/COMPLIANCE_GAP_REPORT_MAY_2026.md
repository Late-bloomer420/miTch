# Compliance Gap Report — May 2026

> **Reconciliation update (2026-05-26):** Batch issuance has since been implemented, but the current evidence supports **49/53 implemented (92%)** plus **4 partial items**. Remaining work: issuer-side `proof.jwt` PoP validation, signed official LOTL/TSL validation, FCAF completion, and formal CC/CAB certification. Canonical per-requirement status: [`EUDI_CIR_MATRIX.md`](EUDI_CIR_MATRIX.md). Original May-25 figures preserved below for history.

## Executive Summary
This report summarizes the compliance state of miTch against the EUDI Wallet Commission Implementing Regulations (CIR) as of May 25, 2026. Significant progress has been made since the March 2026 audit, increasing functional requirement coverage from **77% to 94%**.

The wallet is now functionally complete for **LoA High** (via WebAuthn hardware binding), **Proximity Presentation** (ISO 18013-5), and **GDPR Data Subject Rights** (Erasure & Reporting).

## 1. Requirement Coverage Overview

| Regulation | Total | ✅ Implemented | Coverage |
|---|---|---|---|
| **CIR 2024/2977** (PID & EAA) | 15 | 14 | 93% |
| **CIR 2024/2979** (Integrity & Security) | 15 | 15 | 100% |
| **CIR 2024/2982** (Protocols & Interfaces) | 18 | 17 | 94% |
| **CIR 2024/2981** (Certification) | 5 | 3 | 60% |
| **Grand Total** | **53** | **49** | **92%** |

## 2. Key Accomplishments (Mar-May 2026)

### ✅ Hardware-Bound Identity (LoA High)
Addressed via **ADR-013**. miTch now utilizes platform-native WebAuthn APIs to ensure identity and presentation keys are non-extractable and bound to the device's Secure Element (SE) / Trusted Execution Environment (TEE). This satisfies the core security requirement for eIDAS Level of Assurance "High".

### ✅ Proximity & Offline Presentation
Implemented ISO 18013-5 compliant device engagement (QR-based) and offline presentation. The wallet can now interact with verifiers in no-network scenarios, a critical requirement for EUDI Wallet pilot readiness.

### ✅ Data Subject Rights (GDPR)
Implemented native support for **Data Erasure Requests** (Right to be Forgotten) and **Reporting Mechanisms** for suspicious Relying Parties directly within the Wallet UI. All events are logged in the privacy-preserving audit trail.

### ✅ Protocol Completeness
Finalized support for combined `vp_token` + `id_token` responses (SIOPv2/OID4VP) and validated HAIP response encryption (`direct_post.jwt`).

## 3. Remaining Gaps for Pilot-Readiness

### 🟡 Issuer-Side `proof.jwt` Proof-of-Possession (P1)
The OID4VCI request schema accepts proof material, but `OID4VCIIssuer.issueCredential` still needs cryptographic validation of the holder proof before issuance.

### 🟡 Signed EUDI Trust List Integration (P1)
miTch now has a dynamic JSON trust-list resolver with fail-closed behavior for pilot wiring. For production or official assessment, the resolver must validate a signed official LOTL/TSL source against the configured trust anchor.

### 🟡 Formal Certification (P2)
While functionally compliant, a formal Common Criteria (ISO/IEC 15408) evaluation and audit by an accredited Conformity Assessment Body (CAB) is necessary for official EUDI Wallet designation.

### 🟡 Functional Conformance Assessment Completion (P2)
Evidence artefacts are being assembled, but the open proof and trust-list items must close before miTch can honestly claim complete FCAF readiness.

## 4. Conclusion
miTch has a strong EUDI pilot-readiness baseline, but the current evidence does not support a "fully compliant" or "formal evaluation ready" claim yet. The remaining work is concentrated around holder proof validation, signed trust anchors, and external certification.

---
*Report Generated: 2026-05-25 | Gemini CLI (miTch Compliance Suite)*
