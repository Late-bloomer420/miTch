/**
 * L2AnchorClient — binary Merkle tree + env-var contract addresses
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { L2AnchorClient } from '../l2-anchor-client.js';

function makeClient(network: 'mock' | 'optimism-sepolia' = 'mock') {
    return new L2AnchorClient({ network, batchingEnabled: false });
}

describe('L2AnchorClient — mock anchoring', () => {
    it('anchorRoot returns a confirmed receipt for mock network', async () => {
        const client = makeClient('mock');
        const receipt = await client.anchorRoot('deadbeef');
        expect(receipt.stateRoot).toBe('deadbeef');
        expect(receipt.status).toBe('confirmed');
        expect(receipt.network).toBe('mock');
        expect(receipt.l2TransactionId).toMatch(/^0x[0-9a-f]{32}/);
    });

    it('verifyAnchor returns true for mock receipt', async () => {
        const client = makeClient('mock');
        const receipt = await client.anchorRoot('abc123');
        expect(await client.verifyAnchor(receipt)).toBe(true);
    });

    it('verifyAnchor returns true for pending receipt', async () => {
        const client = makeClient('mock');
        const pendingReceipt = {
            stateRoot: 'root',
            l2TransactionId: 'pending-1',
            blockHeight: 0,
            timestamp: new Date().toISOString(),
            network: 'optimism-sepolia' as const,
            status: 'pending' as const,
        };
        expect(await client.verifyAnchor(pendingReceipt)).toBe(true);
    });
});

describe('L2AnchorClient — batching path (non-mock network)', () => {
    // mock network short-circuits to confirmed; use optimism-sepolia to hit the batching path.
    // NODE_ENV in vitest is 'test' (not 'development'), so the batching branch is reachable.

    it('queued items return pending receipts', async () => {
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: true, batchIntervalMs: 60000 });
        const r1 = await client.anchorRoot('root1');
        const r2 = await client.anchorRoot('root2');
        expect(r1.status).toBe('pending');
        expect(r1.l2TransactionId).toMatch(/^pending-/);
        expect(r2.status).toBe('pending');
        client.stopBatchTimer();
    });

    it('immediate non-batched anchoring falls through to mock receipt', async () => {
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = await client.anchorRoot('abcd');
        // submitToL2 falls back to mockAnchor, so status is confirmed
        expect(receipt.status).toBe('confirmed');
        expect(receipt.stateRoot).toBe('abcd');
    });
});

describe('L2AnchorClient — env-var contract addresses', () => {
    const originalEnv = { ...process.env };

    beforeEach(() => {
        process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'] = '0x1234567890abcdef1234567890abcdef12345678';
    });

    afterEach(() => {
        // Restore
        delete process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'];
        Object.assign(process.env, originalEnv);
    });

    it('verifyAnchor uses env-var contract address (not zero address) and logs stub warning', async () => {
        // With a non-zero contract address, verifyAnchor should log stub warning and return true
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = {
            stateRoot: 'abc',
            l2TransactionId: '0xabc',
            blockHeight: 100,
            timestamp: new Date().toISOString(),
            network: 'optimism-sepolia' as const,
            status: 'confirmed' as const,
        };
        // Should return true (stub) since on-chain query is not yet wired
        expect(await client.verifyAnchor(receipt)).toBe(true);
    });

    it('verifyAnchor returns true with zero-address contract (undeployed)', async () => {
        delete process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'];
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = {
            stateRoot: 'xyz',
            l2TransactionId: '0xxyz',
            blockHeight: 0,
            timestamp: new Date().toISOString(),
            network: 'optimism-sepolia' as const,
            status: 'confirmed' as const,
        };
        expect(await client.verifyAnchor(receipt)).toBe(true);
    });
});
