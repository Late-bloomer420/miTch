// Use core types from shared-types to ensure consistency
export type {
    Hex32,
    AnchorRef,
    AnchorSubmit,
    AnchorBatchReceipt,
    InclusionProof
} from '@mitch/shared-types';

import type { Hex32, AnchorRef } from '@mitch/shared-types';

export interface AnchorServiceConfig {
    maxBatchSize: number;
    maxBatchWindowMs: number;
    dedupeWithinBatch: boolean;
}

export interface AnchorProvider {
    publishRoot(root: Hex32, meta: { batchId: string; count: number }): Promise<AnchorRef>;
}

export interface MerkleBuildResult {
    root: Hex32;
    orderedDecisionHashes: Hex32[];
    leafHashes: Buffer[];
    levels: Buffer[][];
}
