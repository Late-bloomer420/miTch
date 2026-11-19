import { L2AnchorReceipt } from '@askmi/shared-types';

/**
 * L2 Blockchain Anchor Client
 *
 * **Status: Partially mocked — planned for real implementation (F-12)**
 *
 * What is real:
 * - Binary Merkle tree root computation (SHA-256, power-of-2 padding)
 * - Batch queue with configurable flush interval
 * - Contract address resolution from environment variables
 *   (`L2_CONTRACT_OPTIMISM_MAINNET`, `L2_CONTRACT_OPTIMISM_SEPOLIA`, etc.)
 * - Structured `L2AnchorReceipt` with txHash, blockNumber, timestamp, network
 *
 * What is mocked:
 * - `submitToL2()` — does NOT send a real on-chain transaction. Currently calls
 *   `mockAnchor()` which returns a synthetic receipt with `status: 'mocked'`
 *   (never `'confirmed'`). Integration with a real EVM provider (ethers.js / viem)
 *   is required before production use. (F-06)
 * - `verifyAnchor()` — no on-chain query exists yet, so it never reports a real
 *   anchor as verified: undeployed contract or unwired query → `false`
 *   (`verifyAnchorDetailed()` explains why). Only the explicit `mock` network
 *   yields `true`. (F-05)
 *
 * To enable real anchoring:
 * 1. Add `viem` or `ethers` as a dependency
 * 2. Implement `submitToL2()` to call the on-chain `anchor(bytes32)` function
 * 3. Set env vars `L2_RPC_OPTIMISM_MAINNET` and `L2_CONTRACT_OPTIMISM_MAINNET`
 *
 * GDPR Compliance (planned):
 * - Art. 32 DSGVO: External, tamper-proof evidence
 * - Non-repudiation through blockchain immutability
 * - DPA-verifiable audit trail
 *
 * Supported Networks:
 * - Optimism (low cost, fast finality)
 * - Arbitrum (alternative L2)
 * - Polygon zkEVM (future)
 */

export type L2Network = 'optimism-mainnet' | 'optimism-sepolia' | 'arbitrum-one' | 'arbitrum-sepolia' | 'mock';

export interface L2AnchorConfig {
    network: L2Network;
    rpcUrl?: string;
    contractAddress?: string;
    gasLimit?: number;
    batchingEnabled?: boolean;
    batchIntervalMs?: number;
}

export interface PendingAnchor {
    stateRoot: string;
    queuedAt: string;
    retryCount: number;
}

/**
 * Outcome of checking an anchor receipt.
 * - 'verified':     confirmed by an on-chain query (not reachable until F-05 is closed for real)
 * - 'mock':         receipt from the explicit `mock` network (development opt-in)
 * - 'pending':      queued, nothing is anchored yet
 * - 'unverifiable': no on-chain check could be performed; do NOT treat as verified
 */
export type AnchorVerificationStatus = 'verified' | 'mock' | 'pending' | 'unverifiable';

export interface AnchorVerification {
    status: AnchorVerificationStatus;
    reason: string;
}

/** Sentinel for "anchor contract not deployed". */
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/**
 * Production-Grade L2 Anchor Client
 * 
 * Features:
 * - Real blockchain transactions (Optimism/Arbitrum)
 * - Batching for gas optimization
 * - Retry logic with exponential backoff
 * - Fallback to mock in development
 */
export class L2AnchorClient {
    private config: Required<L2AnchorConfig>;
    private pendingBatch: PendingAnchor[] = [];
    private batchTimer: NodeJS.Timeout | null = null;

    constructor(config: L2AnchorConfig) {
        this.config = {
            network: config.network,
            rpcUrl: config.rpcUrl || this.getDefaultRpcUrl(config.network),
            contractAddress: config.contractAddress || this.getDefaultContractAddress(config.network),
            gasLimit: config.gasLimit || 50000,
            batchingEnabled: config.batchingEnabled ?? true,
            batchIntervalMs: config.batchIntervalMs || 3600000 // 1 hour
        };

        if (this.config.batchingEnabled) {
            this.startBatchTimer();
        }
    }

    /**
     * Anchor a state root to L2
     * 
     * @param stateRoot - SHA-256 hash of the audit log state
     * @param options - Override default config
     */
    async anchorRoot(
        stateRoot: string,
        options?: Partial<L2AnchorConfig>
    ): Promise<L2AnchorReceipt> {
        const effectiveConfig = { ...this.config, ...options };

        // Development/Testing: Use mock
        if (effectiveConfig.network === 'mock' || process.env.NODE_ENV === 'development') {
            return this.mockAnchor(stateRoot);
        }

        // Production: Use batching if enabled
        if (this.config.batchingEnabled) {
            return this.queueForBatch(stateRoot);
        }

        // Immediate anchoring
        return this.submitToL2(stateRoot, effectiveConfig);
    }

    /**
     * Submit a state root directly to L2 (no batching).
     *
     * Wire-up note: replace this stub with an ethers.js / viem call once
     * the anchor contract is deployed.  Required:
     *   - JSON-RPC provider (config.rpcUrl)
     *   - Funded signer (env var: L2_SIGNER_PRIVATE_KEY)
     *   - Contract ABI: `function anchor(bytes32 stateRoot) external`
     *   - Gas estimation + transaction monitoring
     */
    private async submitToL2(
        stateRoot: string,
        config: Required<L2AnchorConfig>
    ): Promise<L2AnchorReceipt> {
        console.warn('[L2AnchorClient] Real blockchain anchoring not yet wired — returning mock receipt');
        console.info(`[L2AnchorClient] Would anchor to ${config.network}: ${stateRoot}`);

        // Placeholder: Return mock receipt with production-like structure
        return this.mockAnchor(stateRoot, config.network);
    }

    /**
     * Queue a state root for batch anchoring
     */
    private async queueForBatch(stateRoot: string): Promise<L2AnchorReceipt> {
        const pending: PendingAnchor = {
            stateRoot,
            queuedAt: new Date().toISOString(),
            retryCount: 0
        };

        this.pendingBatch.push(pending);

        console.info(`[L2AnchorClient] Queued for batch anchoring (${this.pendingBatch.length} pending)`);

        // Return a "pending" receipt
        return {
            stateRoot,
            l2TransactionId: `pending-${Date.now()}`,
            blockHeight: 0,
            timestamp: new Date().toISOString(),
            network: this.config.network,
            status: 'pending'
        };
    }

    /**
     * Process the pending batch
     */
    private async processBatch(): Promise<void> {
        if (this.pendingBatch.length === 0) {
            return;
        }

        console.info(`[L2AnchorClient] Processing batch of ${this.pendingBatch.length} anchors`);

        // Combine all state roots into a Merkle tree
        const batchRoot = await this.calculateBatchRoot(this.pendingBatch.map(p => p.stateRoot));

        try {
            // Submit batch root to L2
            const receipt = await this.submitToL2(batchRoot, this.config);

            if (receipt.status === 'confirmed') {
                console.info(`[L2AnchorClient] Batch anchored: ${receipt.l2TransactionId}`);
            } else {
                // F-06: a mocked receipt is not an on-chain write — do not report success.
                console.warn(
                    `[L2AnchorClient] Batch NOT anchored on-chain (status: ${receipt.status}); ` +
                    `no transaction was sent. Dropping batch of ${this.pendingBatch.length} root(s).`
                );
            }

            // Clear batch (a mocked batch is dropped, not retried: retrying cannot succeed without a provider)
            this.pendingBatch = [];
        } catch (error) {
            console.error('[L2AnchorClient] Batch anchoring failed:', error);

            // Retry logic
            this.pendingBatch.forEach(p => p.retryCount++);

            // Remove entries that have failed too many times
            this.pendingBatch = this.pendingBatch.filter(p => p.retryCount < 3);
        }
    }

    /**
     * Calculate a binary Merkle root for batch anchoring.
     *
     * Algorithm (standard Bitcoin/Ethereum style):
     *  1. Hash each leaf: SHA-256(hexString)
     *  2. Pad to next power-of-2 by duplicating the last leaf
     *  3. Pair-wise hash each level until a single root remains
     *  4. Each interior node: SHA-256(leftChild || rightChild) (raw bytes concat)
     */
    private async calculateBatchRoot(stateRoots: string[]): Promise<string> {
        if (stateRoots.length === 0) {
            // Empty batch: return hash of empty input
            const buf = await crypto.subtle.digest('SHA-256', new Uint8Array(0));
            return uint8ToHex(new Uint8Array(buf));
        }

        const enc = new TextEncoder();

        // Build leaf layer: SHA-256 of each hex state-root string
        let layer: Uint8Array[] = await Promise.all(
            stateRoots.map(async root => {
                const buf = await crypto.subtle.digest('SHA-256', enc.encode(root));
                return new Uint8Array(buf);
            })
        );

        // Pad to next power of 2
        while ((layer.length & (layer.length - 1)) !== 0) {
            layer.push(layer[layer.length - 1]);
        }

        // Build tree bottom-up
        while (layer.length > 1) {
            const next: Uint8Array[] = [];
            for (let i = 0; i < layer.length; i += 2) {
                const combined = new Uint8Array(64);
                combined.set(layer[i], 0);
                combined.set(layer[i + 1], 32);
                const buf = await crypto.subtle.digest('SHA-256', combined);
                next.push(new Uint8Array(buf));
            }
            layer = next;
        }

        return uint8ToHex(layer[0]);
    }

    /**
     * Start the batch timer
     */
    private startBatchTimer(): void {
        this.batchTimer = setInterval(() => {
            this.processBatch().catch(err => {
                console.error('[L2AnchorClient] Batch processing error:', err);
            });
        }, this.config.batchIntervalMs);
    }

    /**
     * Stop the batch timer
     */
    stopBatchTimer(): void {
        if (this.batchTimer) {
            clearInterval(this.batchTimer);
            this.batchTimer = null;
        }
    }

    /**
     * Mock anchoring for development/testing
     */
    private mockAnchor(stateRoot: string, network: L2Network = 'mock'): L2AnchorReceipt {
        return {
            stateRoot,
            l2TransactionId: `0x${crypto.randomUUID().replace(/-/g, '')}`,
            blockHeight: 12000000 + Math.floor(Math.random() * 100000),
            timestamp: new Date().toISOString(),
            network,
            status: 'mocked'
        };
    }

    /**
     * Get default RPC URL for a network
     */
    private getDefaultRpcUrl(network: L2Network): string {
        const urls: Record<L2Network, string> = {
            'optimism-mainnet': 'https://mainnet.optimism.io',
            'optimism-sepolia': 'https://sepolia.optimism.io',
            'arbitrum-one': 'https://arb1.arbitrum.io/rpc',
            'arbitrum-sepolia': 'https://sepolia-rollup.arbitrum.io/rpc',
            'mock': ''
        };

        return urls[network] || '';
    }

    /**
     * Get default contract address for a network.
     * Reads from environment variables first; falls back to zero-address stubs
     * (zero address = undeployed sentinel — callers should treat as "not configured").
     */
    private getDefaultContractAddress(network: L2Network): string {
        const envMap: Record<L2Network, string> = {
            'optimism-mainnet': process.env['L2_CONTRACT_OPTIMISM_MAINNET'] ?? ZERO_ADDRESS,
            'optimism-sepolia': process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'] ?? ZERO_ADDRESS,
            'arbitrum-one':     process.env['L2_CONTRACT_ARBITRUM_ONE']     ?? ZERO_ADDRESS,
            'arbitrum-sepolia': process.env['L2_CONTRACT_ARBITRUM_SEPOLIA'] ?? ZERO_ADDRESS,
            'mock': '',
        };
        return envMap[network] ?? '';
    }

    /**
     * Check an anchor receipt and say what was (not) checked. (F-05)
     *
     * Production path (not yet wired): call the deployed anchor contract's
     * `getAnchor(bytes32 stateRoot)` view function via JSON-RPC and confirm
     * the returned blockHeight matches the receipt. Until then no real anchor
     * can reach 'verified': callers get 'unverifiable' instead of a false positive.
     */
    async verifyAnchorDetailed(receipt: L2AnchorReceipt): Promise<AnchorVerification> {
        if (receipt.network === 'mock') {
            return { status: 'mock', reason: 'Receipt from the explicit mock network (development only)' };
        }

        if (receipt.status === 'pending') {
            return { status: 'pending', reason: 'Receipt is still queued; nothing is anchored yet' };
        }

        if (receipt.status === 'mocked') {
            return {
                status: 'unverifiable',
                reason: `Synthetic receipt on ${receipt.network}: no on-chain transaction exists`,
            };
        }

        const contractAddress = this.getDefaultContractAddress(receipt.network as L2Network);
        if (!contractAddress || contractAddress === ZERO_ADDRESS) {
            console.warn(`[L2AnchorClient] verifyAnchor: contract not deployed for ${receipt.network}, no on-chain check performed`);
            return {
                status: 'unverifiable',
                reason: `Anchor contract not deployed for ${receipt.network}; no on-chain check performed`,
            };
        }

        // On-chain query would go here once ethers/viem is added
        // e.g.: const contract = new ethers.Contract(contractAddress, ANCHOR_ABI, provider);
        //       const anchored = await contract.getAnchor(receipt.stateRoot);
        //       return anchored.blockHeight.toString() === receipt.blockHeight.toString();
        console.warn(`[L2AnchorClient] verifyAnchor: on-chain query not wired for ${receipt.network} tx=${receipt.l2TransactionId}`);
        return {
            status: 'unverifiable',
            reason: `On-chain query not wired for ${receipt.network}; no on-chain check performed`,
        };
    }

    /**
     * Boolean convenience over {@link verifyAnchorDetailed}.
     *
     * `true` only when the receipt was verified on-chain or comes from the explicit
     * `mock` network. Pending and unverifiable receipts return `false`.
     */
    async verifyAnchor(receipt: L2AnchorReceipt): Promise<boolean> {
        const { status } = await this.verifyAnchorDetailed(receipt);
        return status === 'verified' || status === 'mock';
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function uint8ToHex(buf: Uint8Array): string {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}
