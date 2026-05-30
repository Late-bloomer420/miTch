# miTch AI-Guardian: Institutional Privacy Infrastructure for the AI Era

## 1. Vision
The **miTch AI-Guardian** is a high-assurance gateway that enables **Verifiable AI Training & Inference**. It solves the "Data Trust Gap" between data owners (individuals/institutions) and AI processors (Model providers/Trainers) by replacing promises with cryptographic proofs.

While typical AI pipelines ingest data and "promise" to delete it or protect PII, AI-Guardian uses the miTch technical primitives to **enforce** privacy through mathematics and hardware-bound keys.

## 2. Technical Primitives (The "Code Reality")
Based on the current miTch implementation, the following primitives form the backbone of AI-Guardian:

| Primitive | Package | Role in AI-Guardian |
|-----------|---------|----------------------|
| **ZKQF (Zero-Knowledge Query Firewall)** | `@mitch/policy-engine` | Filters incoming data to ensure only the absolute minimum required attributes (e.g., non-PII features) reach the training process. |
| **Crypto-Shredding & ShredProof** | `@mitch/secure-memory` | Ensures that data is only usable during a specific training/inference window. Generates a mathematical proof that the decryption key was destroyed. |
| **Tamper-Evident Audit (H1-H5)** | `@mitch/audit-log` | Creates a non-repudiable log of every training data point used, anchored to an L2 blockchain. |
| **Post-Quantum Cryptography (PQC)** | `@mitch/shared-crypto` | Future-proofs the audit trail and data signatures against the long-term threat of quantum decryption (Harvest Now, Decrypt Later). |

## 3. The Lifecycle: "Proof-of-Privacy" Pipeline

### Phase A: Ingestion (The "Privacy Filter")
1. Data arrives as an **SD-JWT VC** (Verifiable Credential).
2. The `PolicyEngine` evaluates the data against the **Training Policy**.
3. **Selective Disclosure** is applied: The Guardian "peels off" all PII (names, precise locations) and only keeps the vector features needed for the AI model.

### Phase B: Processing (The "Ephemeral Window")
1. An `EphemeralKey` is generated for the training batch.
2. The filtered data is decrypted inside an `EphemeralKey.use()` block.
3. The AI training/inference step is executed within this isolated context.
4. **Immediate Destruction:** As soon as the operation completes (or times out), the key is zeroed out in memory.

### Phase C: Finality (The "Compliance Receipt")
1. A `ShredProof` is generated, linking the pre-shred hash to the post-shred (zeroed) state.
2. The **H5-Hardened Audit Event** is created, containing:
   - Hash of the used features (minimization proof).
   - The `ShredProof` (deletion proof).
   - Timestamp and L2 Anchor.
3. This receipt can be presented to regulators (e.g., GDPR auditors) to prove the "Right to be Forgotten" was enforced technically.

## 4. Proposed Extensions (Brainstorming)

### 4.1. "Legal Prompt" - Policy-Enforced Inference
Extend the `PolicyEngine` to intercept AI prompts. If a user asks a medical AI for advice, the AI-Guardian checks if the user has presented a "Doctor" or "Patient" credential before allowing the prompt to reach the LLM.

### 4.2. "Data-Minimization Proxy"
A middleware for companies that use third-party APIs (like OpenAI). Instead of sending raw customer emails, the miTch Proxy replaces sensitive data with anonymized tokens, only "detokenizing" them when they return to the miTch secure zone.

### 4.3. "Quantum-Safe Model Weights"
Use miTch's PQC signatures (`ML-DSA`) to sign the resulting model weights. This proves that the model was produced by a miTch-certified pipeline and has not been tampered with since training.

## 5. Summary
miTch AI-Guardian transforms the project from a "User Wallet" into a **"Strategic Compliance Layer"** for the global AI market. It moves miTch into the B2B and Enterprise sectors, where "Proof of Deletion" and "Verifiable Minimization" are multi-billion dollar requirements.
