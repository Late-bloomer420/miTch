# B2B User Story: The "Verifiable Pharma Insight" (EHDS Case)

## 1. Persona & Context
**Role:** Dr. Elena Vance, Chief Data Officer at *BioVanguard Pharmaceuticals*.
**Goal:** Access real-world patient outcome data for a new cardiovascular drug without violating the EU AI Act or GDPR.
**Constraint:** The data is owned by the *Tirol Regional Hospital Network*, which refuses to export raw datasets due to strict EHDS (European Health Data Space) policies.

## 2. The Narrative (Current State vs. AI-Guardian)

### 2.1. The "Broken" Process (Today)
BioVanguard requests data. The hospital's legal team takes 14 months to draft a Data Sharing Agreement. The IT team creates a "de-identified" CSV. Elena runs her AI model on it, but the "de-identification" was too aggressive (it removed age and zip codes), making the AI model inaccurate. BioVanguard still has to "promise" they deleted the CSV, which the hospital doesn't trust.

### 2.2. The AI-Guardian Flow (Proposed)

**Step 1: The Trust Anchor (Ingestion)**
 BioVanguard presents their **Institutional Verifier Attestation** (miTch primitive) to the Hospital's AI-Guardian Node. The Node verifies BioVanguard is an authorized researcher.

**Step 2: The Policy Negotiation (ZKQF)**
BioVanguard submits their AI Training Script. The Hospital's miTch **PolicyEngine** (ZKQF) inspects the script. 
*   **Action:** The PolicyEngine allows the script to access `bloodPressure` and `drugDosage`, but automatically blocks access to `patientName` and `exactBirthDate`.
*   **Action:** It injects a "Differential Privacy" layer, ensuring the AI model only sees patterns, not individuals.

**Step 3: The Ephemeral Processing (EPU)**
The miTch Node generates an **EphemeralKey**. 
*   The patient data is decrypted ONLY inside the Secure Execution Environment (SEE).
*   The AI model trains. Raw data never touches a disk; it stays in volatile memory.

**Step 4: The Shred-Proof Finality**
As soon as the training finishes, the miTch Node triggers **Crypto-Shredding**.
*   **Result:** A `ShredProof` is generated. It mathematically proves the decryption key is gone.
*   **Evidence:** An **H5-Hardened Audit Log** entry is created, anchored to the L2 blockchain.

## 3. The "Aha!" Moment (Value Proposition)
BioVanguard receives the trained AI Model Weights. The Hospital receives a **Compliance Receipt**.
Elena can now show her board: "We have the model, and we have cryptographic proof that we never possessed the raw data and that it no longer exists in our environment."

## 4. Technical Mapping (Source Code Alignment)
| Story Step | miTch Technical Primitive | Status |
|------------|---------------------------|--------|
| Auth BioVanguard | `VerifierSDK` + `DID:web` | ✅ Ready |
| Filter PII | `PolicyEngine` (ZKQF) | ✅ Ready |
| Isolate Training | `EphemeralKey.use()` | ✅ Ready |
| Prove Deletion | `ShredProof` + `L2Anchor` | ✅ Ready |
| Long-term Audit | `PQCSigner` (Post-Quantum) | ✅ Ready |

## 5. Potential Nutzersicht (The Quote)
*"Für uns ist miTch nicht mehr nur eine Wallet, sondern das 'Zollamt' für unsere Daten. Wir lassen die KI rein, lassen sie arbeiten, und miTch sorgt dafür, dass sie beim Verlassen nichts mitgehen lässt, was sie nicht darf."*
