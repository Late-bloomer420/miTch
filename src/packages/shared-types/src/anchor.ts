/**
 * Anchor types shared between services.
 * L2 Anchoring Service Contracts
 */

/**
 * 32-byte hex string (64 hex chars).
 */
export type Hex32 = string;

/**
 * Reference to a published anchor (e.g., Merkle root on L2).
 */
export interface AnchorRef {
    provider: 'TRANSPARENCY_LOG' | 'PUBLIC_LEDGER' | 'INTERNAL_WORM' | 'DEV_NULL';
    ref: string;
    timestamp: string;
}

/**
 * Submission payload for anchoring a decision hash.
 */
export interface AnchorSubmit {
    decisionHash: Hex32;
    occurredAt?: string; // ISO String (client-provided hint)
}

/**
 * Receipt returned after anchoring a batch.
 */
export interface AnchorBatchReceipt {
    batchId: string;
    root: Hex32;
    timestamp: string;
    includedHashes: Hex32[];
    proof?: InclusionProof; // Enriched receipt if specific to a request
}

/**
 * Merkle inclusion proof for a leaf hash.
 */
export interface InclusionProof {
    root: Hex32;
    target: Hex32;
    siblings: string[]; // Hex strings of sibling nodes
}
