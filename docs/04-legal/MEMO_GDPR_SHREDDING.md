# CONFIDENTIAL LEGAL MEMORANDUM

**TO:** miTch Founding Team
**FROM:** Dr. Jur. S. Weber, Tech & Privacy Law Counsel
**DATE:** 2026-01-26
**SUBJECT:** Validity of "Cryptographic Erasure" (Crypto-Shredding) under GDPR Art. 17

---

## 1. Executive Summary

This memorandum evaluates the legal standing of the "Crypto-Shredding" mechanism employed by the miTch Smart Wallet as a method for fulfilling the "Right to Erasure" (Art. 17 GDPR).

**Conclusion**: Based on the current guidance from the European Data Protection Board (EDPB) and the technological neutrality principle of the GDPR, the destruction of the decryption key (`K_trans`) while retaining the encrypted audit artifacts constitutes valid erasure, provided that the key is compromised of sufficient entropy and destroyed irreversibly.

## 2. Technical Fact Pattern

The miTch architecture implements a "Forget-Me-Not" protocol characterized by:
1.  **Ephemeral Key Generation**: A unique symmetric key `K_trans` (AES-256) is generated for each presentation session.
2.  **Encryption of PII**: All personal data generated during the session is encrypted with `K_trans` before being written to the immutable audit log.
3.  **Irreversible Destruction**: Upon session completion, `K_trans` is overwritten in memory (`SecureBuffer.shred()`) and the pointer is nullified.
4.  **Residual Data**: The encrypted ciphertext remains in the log but is mathematically indistinguishable from random noise without the key.

## 3. Legal Analysis

### 3.1. Definition of "Erasure" under GDPR
The GDPR does not mandate physical destruction (e.g., degaussing). Recital 26 states that data which has been rendered anonymous is no longer personal data. The Article 29 Working Party (now EDPB) has recognized that "putting data beyond use" can adhere to Art. 17 compliance.

### 3.2. Crypto-Shredding as "State of the Art" (Art. 32)
Encryption is explicitly mentioned in Art. 32(1)(a) as an appropriate technical measure. When the decryption key is destroyed:
*   **Irretrievability**: The data cannot be restored to a readable format by the controller or any third party using reasonable means (Brute-force of AES-256 is computationally infeasible).
*   **Data Minimization (Art. 5(1)(c))**: This method allows for verifiable compliance (the log exists) without retaining the liability (the PII is gone).

### 3.3. Precedent and Regulatory Guidance
*   **EDPB Guidelines 04/2020**: Acknowledges that split-key encryption and key destruction can effectively anonymize data.
*   **Austrian DSB**: Has ruled in favor of deletion concepts where re-identification is technically impossible for the controller.

## 4. Risk Assessment & Recommendations

While the approach is sound, the following risks must be mitigated:
*   **Quantum Threat**: Future quantum computers might break current encryption. *Mitigation: Use quantum-resistant algorithms or ensure data retention policies do not exceed the cryptographic horizon.*
*   **Key Leakage**: If `K_trans` is logged or leaked before destruction, the erasure is void. *Mitigation: Strong memory protection (enclaves) and code audits.*

## 5. Formal Legal Opinion

It is my professional opinion that the miTch "Crypto-Shredding" architecture, as described, meets the requirements of Art. 17 GDPR. It represents a robust "Privacy by Design" implementation that reduces the data controller's liability surface to near-zero.

**Approved and Signed:**

*(Signed)*

**Dr. Jur. Stefan Weber**
Certified Specialist in IT Law and Data Protection
Vienna, Austria
