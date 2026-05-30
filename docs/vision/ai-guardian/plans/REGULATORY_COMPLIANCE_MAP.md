# miTch Regulatory Compliance Map: AI Act, GDPR & EHDS

This document maps the technical implementation of miTch to the key requirements of European digital regulations. It serves as the "Compliance Blueprint" for the **AI-Guardian** and the broader miTch ecosystem.

## 1. EU AI Act (Regulation 2024/1689)

| AI Act Requirement | Article | miTch Implementation | Status |
|---|---|---|---|
| **Data Governance & Training Data** | Art. 10 | **ZKQF (Zero-Knowledge Query Firewall):** Filters and anonymizes datasets before ingestion. Ensures no unintended PII enters the training process. | ✅ |
| **Transparency to Users** | Art. 13 | **Decision Capsules:** Human-readable explanations of why a specific data processing policy was applied or denied. | ✅ |
| **Cybersecurity & Robustness** | Art. 15 | **Post-Quantum Cryptography (PQC):** Hybrid signatures (ML-DSA) protect long-term audit data against quantum threats. | ✅ |
| **Technical Documentation** | Art. 11 / 16 | **H5-Hardened Audit Log:** Automatically generates a comprehensive, tamper-evident record of all AI data interactions. | ✅ |
| **Right to Explanation** | Art. 86 | **Explanation Request Layer:** Standardized protocol for users to request and store explanations for automated decisions. | ✅ |
| **Accuracy & Error Handling** | Art. 15(3) | **Deny Code Catalog:** Structured error handling (21_Deny_Code_Catalog.md) ensuring precise feedback instead of "black box" failures. | ✅ |

## 2. GDPR (General Data Protection Regulation)

| GDPR Requirement | Article | miTch Implementation | Status |
|---|---|---|---|
| **Data Minimization** | Art. 5(1)(c) | **SD-JWT Selective Disclosure:** Users only share the specific claims (e.g., "Age > 18") needed, never the full identity. | ✅ |
| **Right to Erasure (Forgotten)** | Art. 17 | **Crypto-Shredding (ShredProof):** Mathematical proof that the decryption key for a specific dataset was destroyed. | ✅ |
| **Integrity & Confidentiality** | Art. 5(1)(f) | **Secure Memory & Hardware Binding:** Keys are stored in hardware-bound SE/TEE and zeroed out after ephemeral use. | ✅ |
| **Privacy by Design & Default** | Art. 25 | **Fail-Closed Policy Engine:** The default state for any unknown or non-compliant request is DENY. | ✅ |
| **Records of Processing** | Art. 30 | **Audit Service:** Non-repudiable transaction logs geankert on L2. | ✅ |
| **Data Portability** | Art. 20 | **Standardized Formats:** Full support for W3C VC, mDoc, and SD-JWT for interoperable data movement. | ✅ |

## 3. EHDS (European Health Data Space)

| EHDS Requirement | Article | miTch Implementation | Status |
|---|---|---|---|
| **Secondary Use Control** | Art. 33 / 35 | **Secondary-Use Opt-Out:** Hardcoded policy in the `policy-engine` to block research access by default. | ✅ |
| **Interoperable Health Data** | Art. 12 | **W3C VC + SD-JWT:** Support for the European Health Data exchange formats. | ✅ |
| **Data Access Permits** | Art. 46 | **Trust List (TSL) Integration:** Verifies that a researcher has a valid HDAB (Health Data Access Body) permit. | ✅ |
| **Right to Control Access** | Art. 8 | **Local Policy Sovereignty:** The user (or data owner) decides on their own device who sees what clinical data. | ✅ |

## 4. EUDI / eIDAS 2.0

| EUDI Requirement | ARF Reference | miTch Implementation | Status |
|---|---|---|---|
| **High LoA (Level of Assurance)** | ARF 1.3 | **WebAuthn Hardware Binding:** Identity keys are bound to the device's Secure Element. | ✅ |
| **Trust List Management** | ARF 1.4 | **EUDITrustListResolver:** Real-time fetching and validation of the EU LOTL (List of Trusted Lists). | ✅ |
| **Qualified Signatures** | eIDAS Art. 25 | **Brainpool & ECDSA Support:** Full cryptographic compatibility with BSI TR-03116. | ✅ |

---

## Strategic Value: The "Liability Shift"
By implementing these regulations **in the code**, miTch allows organizations to shift from "Self-Certification" (claiming to be compliant) to **"Technical Evidence"** (proving compliance through cryptographic logs). This reduces legal risk and insurance premiums for AI processors.
