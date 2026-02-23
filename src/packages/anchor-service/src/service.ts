import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto'; // Use node crypto for UUID in service
import { Hex32, AnchorSubmit, AnchorBatchReceipt } from '@mitch/shared-types';
import { buildMerkleTree, getInclusionProof } from './merkle.js';
import { AnchorServiceConfig, AnchorProvider } from './types.js';

export class InMemoryAnchorService extends EventEmitter {
    private queue: Hex32[] = [];
    private timer: NodeJS.Timeout | null = null;

    // T-41: Map-based Promise completion to prevent EventEmitter memory leak
    private pendingSubmissions = new Map<string, {
        resolve: (proof: AnchorBatchReceipt) => void;
        reject: (reason: any) => void;
        timeout: NodeJS.Timeout;
    }>();

    private config: AnchorServiceConfig;
    private provider: AnchorProvider;

    constructor(config: AnchorServiceConfig, provider: AnchorProvider) {
        super();
        this.config = config;
        this.provider = provider;
    }

    /**
     * Accepts a decision hash from a Wallet.
     * Returns a promise that resolves when the hash is anchored.
     */
    public submit(submission: AnchorSubmit): Promise<AnchorBatchReceipt> {
        return new Promise((resolve, reject) => {
            // 1. Validate Input (Hex 32 bytes)
            if (!/^[a-f0-9]{64}$/.test(submission.decisionHash)) {
                return reject(new Error("Invalid Hash Format"));
            }

            // 2. T-41: Register Promise Handler (O(1) lookup)
            // T-42: Add TTL Cleanup to prevent zombie entries
            const timeout = setTimeout(() => {
                if (this.pendingSubmissions.has(submission.decisionHash)) {
                    this.pendingSubmissions.delete(submission.decisionHash);
                    reject(new Error("Anchor Timeout: Batch not processed in time"));
                }
            }, this.config.maxBatchWindowMs * 2); // 2x window as safety margin

            this.pendingSubmissions.set(submission.decisionHash, { resolve, reject, timeout });

            // 3. Add to Queue
            this.queue.push(submission.decisionHash);

            // 4. Trigger Batch if full
            if (this.queue.length >= this.config.maxBatchSize) {
                this.flush();
            } else if (!this.timer) {
                // Start timer if not running
                this.timer = setTimeout(() => this.flush(), this.config.maxBatchWindowMs);
            }
        });
    }

    private async flush() {
        if (this.queue.length === 0) return;

        // Clear timer
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        // Snap the queue
        const currentBatch = [...this.queue];
        this.queue = [];

        try {
            // Build Tree
            const tree = buildMerkleTree(currentBatch);

            // Publish Root to Provider (e.g., Ledger / Transparency Log)
            const anchorRef = await this.provider.publishRoot(tree.root, {
                batchId: randomUUID(),
                count: currentBatch.length
            });

            // Emit success (Global Bus)
            const receiptArgs: AnchorBatchReceipt = {
                root: tree.root,
                batchId: anchorRef.ref,
                timestamp: anchorRef.timestamp,
                includedHashes: tree.orderedDecisionHashes
            };
            this.emit('batch_committed', receiptArgs);

            // T-41: Deterministically resolve pending promises
            for (const hash of currentBatch) {
                const handler = this.pendingSubmissions.get(hash);
                if (handler) {
                    clearTimeout(handler.timeout); // Clear TTL

                    try {
                        const proof = getInclusionProof(tree, hash);
                        handler.resolve({
                            ...receiptArgs,
                            proof
                        });
                    } catch (e) {
                        handler.reject(e);
                    }
                    this.pendingSubmissions.delete(hash); // O(1) Cleanup
                }
            }

        } catch (err) {
            console.error("Anchoring Failed", err);

            // Fail all pending promises for this batch
            for (const hash of currentBatch) {
                const handler = this.pendingSubmissions.get(hash);
                if (handler) {
                    clearTimeout(handler.timeout);
                    handler.reject(err);
                    this.pendingSubmissions.delete(hash);
                }
            }

            this.emit('batch_failed', err);
        }
    }
}
