# Compliance Gap Report — May 2026

> **Reconciliation update (2026-05-26):** Batch Issuance has since been implemented, raising coverage to **51/53 (96%)**. The two remaining items are **live TSL integration** (the resolver currently uses mock/static data) and **formal CC certification** (external CAB). Canonical per-requirement status: [`EUDI_CIR_MATRIX.md`](EUDI_CIR_MATRIX.md). Original May-25 figures preserved below for history.

## Executive Summary
This report summarizes the compliance state of miTch against the EUDI Wallet Commission Implementing Regulations (CIR) as of May 25, 2026. Significant progress has been made since the March 2026 audit, increasing functional requirement coverage from **77% to 94%**.

The wallet is now functionally complete for **LoA High** (via WebAuthn hardware binding), **Proximity Presentation** (ISO 18013-5), and **GDPR Data Subject Rights** (Erasure & Reporting).

## 1. Requirement Coverage Overview

| Regulation | Total | ✅ Implemented | Coverage |
|---|---|---|---|
| **CIR 2024/2977** (PID & EAA) | 15 | 14 | 93% |
| **CIR 2024/2979** (Integrity & Security) | 15 | 15 | 100% |
| **CIR 2024/2982** (Protocols & Interfaces) | 18 | 17 | 94% |
| **CIR 2024/2981** (Certification) | 5 | 4 | 80% |
| **Grand Total** | **53** | **50** | **94%** |

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

### 🟡 EUDI Trust List Integration (P1)
Currently, miTch uses a static allowlist of trusted verifiers and issuers. For a live pilot, integration with the official European Trusted List of Trust Service Providers (TSLs) via an eIDAS node is required.

### 🟡 Formal Certification (P2)
While functionally compliant, a formal Common Criteria (ISO/IEC 15408) evaluation and audit by an accredited Conformity Assessment Body (CAB) is necessary for official EUDI Wallet designation.

### 🔴 Batch Issuance (P2)
Support for OID4VCI §7 (batch_credential endpoint) is not yet implemented. This is required for high-volume issuance scenarios but is not a blocker for initial low-volume pilot phases.

## 4. Conclusion
miTch is technically ready for the **EUDI Wallet Pilot Phase**. The architecture is robust, privacy-first, and aligned with the latest implementing acts. The remaining work focuses primarily on organizational trust anchors and formal certification processes.

---
*Report Generated: 2026-05-25 | Gemini CLI (miTch Compliance Suite)*
