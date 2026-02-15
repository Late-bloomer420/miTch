import { describe, it, expect, vi } from 'vitest';
import { buildMerkleTree, getInclusionProof } from '../src/merkle.js';
import { InMemoryAnchorService } from '../src/service.js';
import { Hex32 } from '@mitch/shared-types';

describe('Merkle Logic', () => {
    // deterministic mock hashes
    const hashA = 'a'.repeat(64) as Hex32;
    const hashB = 'b'.repeat(64) as Hex32;
    const hashC = 'c'.repeat(64) as Hex32;

    it('builds a deterministic root (sorting)', () => {
        const tree1 = buildMerkleTree([hashA, hashB]);
        const tree2 = buildMerkleTree([hashB, hashA]); // Reversed input

        expect(tree1.root).toBe(tree2.root); // Roots must match (lexicographical sort)
        expect(tree1.orderedDecisionHashes).toEqual([hashA, hashB]);
    });

    it('generates valid inclusion proofs', () => {
        const tree = buildMerkleTree([hashA, hashB, hashC]);
        const proof = getInclusionProof(tree, hashC);

        expect(proof.target).toBe(hashC);
        expect(proof.root).toBe(tree.root);
        expect(proof.siblings.length).toBeGreaterThan(0);
    });
});

describe('Anchor Service', () => {
    it('batches requests and emits proofs', async () => {
        const mockProvider = {
            publishRoot: vi.fn().mockResolvedValue({
                ref: 'batch_1',
                timestamp: new Date().toISOString(),
                provider: 'DEV_NULL'
            })
        };

        const service = new InMemoryAnchorService({
            maxBatchSize: 2,
            maxBatchWindowMs: 1000,
            dedupeWithinBatch: true
        }, mockProvider);

        const h1 = '1'.repeat(64) as Hex32;
        const h2 = '2'.repeat(64) as Hex32;

        // Submit two hashes (triggering size limit 2)
        const [r1, r2] = await Promise.all([
            service.submit({ decisionHash: h1 }),
            service.submit({ decisionHash: h2 })
        ]);

        expect(r1.batchId).toBe('batch_1');
        expect(r1.proof?.target).toBe(h1);
        expect(r2.proof?.target).toBe(h2);

        // Ensure provider was called only once for the batch
        expect(mockProvider.publishRoot).toHaveBeenCalledTimes(1);
    });
});
