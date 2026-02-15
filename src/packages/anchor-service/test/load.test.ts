
import { describe, it, expect, vi } from 'vitest';
import { InMemoryAnchorService } from '../src/service.js';
import { AnchorProvider, AnchorServiceConfig } from '../src/types.js';
import { randomBytes } from 'node:crypto';

// Mock Provider
const mockProvider: AnchorProvider = {
    publishRoot: vi.fn().mockImplementation(async (root) => ({
        ref: `tx-${root.substring(0, 8)}`,
        timestamp: Date.now()
    }))
};

const config: AnchorServiceConfig = {
    maxBatchSize: 1000,
    maxBatchWindowMs: 50,
    dedupeWithinBatch: true
};

describe('Anchor Service Load Test (T-43)', () => {
    it('should handle 10,000 concurrent submissions without memory leak', async () => {
        const service = new InMemoryAnchorService(config, mockProvider);
        const PENDING_COUNT = 10_000;

        // Generate valid hashes
        const hashes = Array.from({ length: PENDING_COUNT }, () =>
            randomBytes(32).toString('hex')
        );

        const start = performance.now();
        console.log(`🚀 Starting Load Test via T-43: ${PENDING_COUNT} requests...`);

        // Fire all requests concurrently
        const promises = hashes.map(hash => service.submit({ decisionHash: hash }));

        // Wait for all
        const results = await Promise.all(promises);

        const end = performance.now();
        console.log(`✅ Processed ${PENDING_COUNT} requests in ${(end - start).toFixed(2)}ms`);

        // Verify
        expect(results.length).toBe(PENDING_COUNT);
        expect(mockProvider.publishRoot).toHaveBeenCalled(); // Should have flushed multiple batches

        // Memory Leak Check: Ensure internal map is empty
        // @ts-ignore - Accessing private property for testing
        expect(service.pendingSubmissions.size).toBe(0);

        // Verify Integrity (First and Last)
        expect(results[0].includedHashes).toContain(hashes[0]);
        expect(results[PENDING_COUNT - 1].includedHashes).toContain(hashes[PENDING_COUNT - 1]);
    }, 10000); // 10s timeout
});
