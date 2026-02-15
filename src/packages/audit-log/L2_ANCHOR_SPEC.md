# T-28: L2-Anchor Module Specification (Cross-Chain Integrity)

## 1. Objective
Establish an air-gap between the local wallet storage and the "Global Source of Truth" to prevent suppression or re-serialization attacks on the Audit Log. By anchoring the Merkle Root of the log to a public Distributed Ledger (L2), we create a "Temporal Non-Repudiation" guarantee.

## 2. Technical Design: "The Blind Anchor"

### 2.1 State Representation
The `StateRoot` is the SHA-256 hash of the current `AuditLogExport` (excluding the signature). This represents the entire history of the wallet in 32 bytes.

### 2.2 Anchoring Workflow
1.  **Merkle Calculation**: The `AuditLog` generates the `reportHash`.
2.  **L2 Submission**: The wallet sends the `reportHash` + `walletId` (hashed) to a "Blind Anchor" smart contract.
    - **Privacy**: No actual log entries are sent. The verifier/auditor cannot reconstruct anything from the hash.
3.  **Receipt Retrieval**: The L2 returns a `transactionHash` and a `blockTimestamp`.
4.  **Local Binding**: These values are stored in a new local table `anchors` and appended to the *next* Audit Log entry as metadata, creating a "Back-Link" from the chain.

## 3. Data Structure
```typescript
export interface L2AnchorReceipt {
    stateRoot: string;        // The anchored hash
    l2TransactionId: string;   // Transaction Hash on L2
    blockHeight: number;       // Block number
    timestamp: string;         // Confirmation time
    network: string;           // e.g., 'mitch-mainnet-l2'
}
```

## 4. Verification Logic (Auditor)
An auditor verifying a report will:
1.  Recalculate the `reportHash` of the provided Audit Log Export.
2.  Consult the public L2 Explorer for the `walletId` and verify if a matching `stateRoot` exists at the claimed transaction ID.
3.  Result: If they match, the log is proven to have existed exactly in this state at the recorded time.

## 5. Security Property
- **Non-Suppression**: An attacker cannot "forget" a key creation event because the state root of the log containing that event is already immutable on-chain.
- **Rollback Protection**: If an attacker reverts the wallet to yesterday's state, the DPA will find that the *latest* anchor on-chain does not match the provided local history.
