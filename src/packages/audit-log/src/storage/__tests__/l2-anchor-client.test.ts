/**
 * L2AnchorClient — binary Merkle tree + env-var contract addresses
 *
 * F-05 / F-06: the client must never claim an on-chain write or an on-chain
 * verification that did not happen. Mocked submissions carry status 'mocked',
 * and verification without an on-chain check is never reported as verified.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { L2AnchorClient } from '../l2-anchor-client.js';

function makeClient(network: 'mock' | 'optimism-sepolia' = 'mock') {
    return new L2AnchorClient({ network, batchingEnabled: false });
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe('L2AnchorClient — mock anchoring', () => {
    it('anchorRoot returns a mocked (not confirmed) receipt for mock network', async () => {
        const client = makeClient('mock');
        const receipt = await client.anchorRoot('deadbeef');
        expect(receipt.stateRoot).toBe('deadbeef');
        expect(receipt.status).toBe('mocked');
        expect(receipt.network).toBe('mock');
        expect(receipt.l2TransactionId).toMatch(/^0x[0-9a-f]{32}/);
    });

    it('verifyAnchor returns true for a receipt from the explicit mock network', async () => {
        const client = makeClient('mock');
        const receipt = await client.anchorRoot('abc123');
        expect(await client.verifyAnchor(receipt)).toBe(true);
    });

    it('verifyAnchorDetailed labels a mock-network receipt as mock', async () => {
        const client = makeClient('mock');
        const receipt = await client.anchorRoot('abc123');
        const result = await client.verifyAnchorDetailed(receipt);
        expect(result.status).toBe('mock');
    });

    it('verifyAnchor returns false for a pending receipt (nothing is anchored yet)', async () => {
        const client = makeClient('mock');
        const pendingReceipt = {
            stateRoot: 'root',
            l2TransactionId: 'pending-1',
            blockHeight: 0,
            timestamp: new Date().toISOString(),
            network: 'optimism-sepolia' as const,
            status: 'pending' as const,
        };
        expect(await client.verifyAnchor(pendingReceipt)).toBe(false);
        expect((await client.verifyAnchorDetailed(pendingReceipt)).status).toBe('pending');
    });
});

describe('L2AnchorClient — batching path (non-mock network)', () => {
    // mock network short-circuits to a mocked receipt; use optimism-sepolia to hit the batching path.
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

    it('F-06: immediate non-batched anchoring on a real network never reports confirmed', async () => {
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        vi.spyOn(console, 'info').mockImplementation(() => {});
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = await client.anchorRoot('abcd');
        // submitToL2 has no provider wired, so the receipt is synthetic.
        expect(receipt.status).toBe('mocked');
        expect(receipt.stateRoot).toBe('abcd');
    });

    it('F-06: processBatch does not report a mocked submission as anchored', async () => {
        const info = vi.spyOn(console, 'info').mockImplementation(() => {});
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const client = new L2AnchorClient({
            network: 'optimism-sepolia',
            batchingEnabled: true,
            batchIntervalMs: 20,
        });
        await client.anchorRoot('root1');

        await vi.waitFor(() => {
            const warned = warn.mock.calls.map(c => String(c[0]));
            expect(warned.some(m => m.includes('NOT anchored on-chain'))).toBe(true);
        });
        client.stopBatchTimer();

        const infos = info.mock.calls.map(c => String(c[0]));
        expect(infos.some(m => m.includes('Batch anchored'))).toBe(false);
    });
});

describe('L2AnchorClient — env-var contract addresses', () => {
    const originalEnv = { ...process.env };

    beforeEach(() => {
        process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'] = '0x1234567890abcdef1234567890abcdef12345678';
        vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        // Restore
        delete process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'];
        Object.assign(process.env, originalEnv);
    });

    function confirmedReceipt(stateRoot: string) {
        return {
            stateRoot,
            l2TransactionId: `0x${stateRoot}`,
            blockHeight: 100,
            timestamp: new Date().toISOString(),
            network: 'optimism-sepolia' as const,
            status: 'confirmed' as const,
        };
    }

    it('F-05: verifyAnchor returns false while the on-chain query is not wired, even with a contract address', async () => {
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = confirmedReceipt('abc');
        expect(await client.verifyAnchor(receipt)).toBe(false);

        const detailed = await client.verifyAnchorDetailed(receipt);
        expect(detailed.status).toBe('unverifiable');
        expect(detailed.reason).toMatch(/not wired|no on-chain/i);
    });

    it('F-05: verifyAnchor returns false with zero-address contract (undeployed)', async () => {
        delete process.env['L2_CONTRACT_OPTIMISM_SEPOLIA'];
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = { ...confirmedReceipt('xyz'), blockHeight: 0 };
        expect(await client.verifyAnchor(receipt)).toBe(false);

        const detailed = await client.verifyAnchorDetailed(receipt);
        expect(detailed.status).toBe('unverifiable');
        expect(detailed.reason).toMatch(/not deployed/i);
    });

    it('F-05: a synthetic (mocked) receipt on a real network is never verified', async () => {
        const client = new L2AnchorClient({ network: 'optimism-sepolia', batchingEnabled: false });
        const receipt = { ...confirmedReceipt('syn'), status: 'mocked' as const };
        expect(await client.verifyAnchor(receipt)).toBe(false);

        const detailed = await client.verifyAnchorDetailed(receipt);
        expect(detailed.status).toBe('unverifiable');
        expect(detailed.reason).toMatch(/synthetic|mock/i);
    });
});
