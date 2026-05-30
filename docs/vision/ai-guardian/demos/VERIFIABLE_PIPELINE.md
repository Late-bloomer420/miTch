# Interactive Demo Spec: "The Verifiable AI Pipeline"

## 1. Objective
To demonstrate the technical reality of the AI-Guardian by simulating a secure training run. The user (Auditor/Partner) can witness the data ingestion, the automated minimization, the ephemeral window, and the final shred-receipt.

## 2. Demo Layout (Single-Page Dashboard)

The demo is a "Live Monitoring Cockpit" divided into three visual zones:

### Zone 1: The Ingestion Stream (Left)
- **Visual:** A scrolling log of incoming data packets (SD-JWT VCs).
- **Trigger:** Button "Simulate Batch Ingestion" (e.g., 50 Patient Records).
- **Detail:** Shows raw claims (e.g., `name`, `age`, `blood_pressure`) as they hit the gateway.

### Zone 2: The Guardian SEE (Center - "The Black Box")
- **Visual:** A secure-looking container icon.
- **Minimization View:** Shows the `@mitch/policy-engine` in action. Names and precise IDs are "peeled off" and replaced with anonymized hashes.
- **Ephemeral Timer:** A live countdown (e.g., 10 seconds) during which the AI-Training is "active". 
- **The "Big Flash":** A visual effect when the timer hits zero, representing the `shredInternal()` call.

### Zone 3: The Audit Evidence (Right)
- **The Compliance Receipt:** Automatically populates with a `ShredProof` JSON.
- **L2 Anchor Link:** Shows a mock transaction ID proving the event was geankert.
- **Download Button:** "Download ISO-Audit-Ready Evidence Pack".

## 3. Technical Implementation (Using existing Mocks)

### 3.1. Data Source (Issuer-Mock)
- **Role:** Simulates the Hospital.
- **Modification:** Add a `/v1/ai-training-set` endpoint that returns a bundle of signed SD-JWTs with mixed PII and clinical data.

### 3.2. Processing (Verifier-Demo Backend)
- **Role:** Acts as the AI-Guardian Node.
- **Logic:** 
  1. Receive the bundle.
  2. Use `trustListResolver` to verify the Hospital.
  3. Use `PolicyEngine` to filter for a specific "Clinical Research" policy.
  4. Wrap the result in an `EphemeralKey.use()` block.
  5. On cleanup, capture the `getShredProof()` output.

### 3.3. UI (New Demo View in Wallet-PWA or separate React app)
- **Component:** `AIGuardianCockpit.tsx`
- **State Management:** Tracks the transition from `INGESTING` -> `PROCESSING` -> `SHREDDED`.

## 4. The "Key Moment" for the User
During the **Processing Phase**, the user can click a button "Try to Access Raw Data". 
- **Result:** The system returns `Access Denied: Key is volatile and restricted to EPU scope`.
- **Post-Shred:** The user tries again.
- **Result:** The system returns `Error: Key Material zeroed. Pre-hash mismatch.`

## 5. Summary of Demo Value
This demo proves that miTch isn't just a UI concept. It uses the **actual cryptographic lifecycle** (SD-JWT -> Policy Filter -> Ephemeral Key -> Shred Proof) to provide a level of data safety that is currently missing in the AI market.
