/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * G-09: L2/Blockchain anchoring provider stubs.
 */
import { describe, test, expect, beforeEach } from 'vitest';
import { EthereumL2AnchorProvider } from '../src/providers/ethereum-l2.js';
import { TransparencyLogAnchorProvider } from '../src/providers/transparency-log.js';
import { InMemoryAnchorService } from '../src/service.js';
import type { Hex32 } from '@mitch/shared-types';

const TEST_ROOT = 'a'.repeat(64) as Hex32;
const TEST_META = { batchId: 'batch-001', count: 3 };

describe('G-09: EthereumL2AnchorProvider (stub)', () => {
  let provider: EthereumL2AnchorProvider;

  beforeEach(() => {
    provider = new EthereumL2AnchorProvider({
      network: 'polygon',
      contractAddress: '0x1234567890abcdef1234567890abcdef12345678',
      rpcUrl: 'https://polygon-rpc.com',
    });
  });

  test('publishRoot returns a valid AnchorRef with 0x-prefixed tx hash', async () => {
    const ref = await provider.publishRoot(TEST_ROOT, TEST_META);

    expect(ref.ref).toMatch(/^0x[a-f0-9]+$/);
    expect(ref.timestamp).toBeGreaterThan(0);
  });

  test('publishRoot embeds network and contract metadata', async () => {
    const ref = await provider.publishRoot(TEST_ROOT, TEST_META) as any;

    expect(ref.network).toBe('polygon');
    expect(ref.contractAddress).toMatch(/^0x/);
    expect(ref.batchId).toBe('batch-001');
    expect(ref.leafCount).toBe(3);
  });

  test('different roots produce different refs (no collision)', async () => {
    const rootA = 'a'.repeat(64) as Hex32;
    const rootB = 'b'.repeat(64) as Hex32;

    const refA = await provider.publishRoot(rootA, TEST_META);
    const refB = await provider.publishRoot(rootB, TEST_META);

    expect(refA.ref).not.toBe(refB.ref);
  });

  test('integrates with InMemoryAnchorService as drop-in provider', async () => {
    const service = new InMemoryAnchorService(
      { maxBatchSize: 2, maxBatchWindowMs: 100, dedupeWithinBatch: true },
      provider
    );

    const hashA = 'a'.repeat(64) as Hex32;
    const hashB = 'b'.repeat(64) as Hex32;

    const [receiptA, receiptB] = await Promise.all([
      service.submit({ decisionHash: hashA }),
      service.submit({ decisionHash: hashB }),
    ]);

    expect(receiptA.root).toBeDefined();
    expect(receiptB.root).toBeDefined();
    expect(receiptA.root).toBe(receiptB.root); // same batch
  });
});

describe('G-09: TransparencyLogAnchorProvider (stub)', () => {
  let provider: TransparencyLogAnchorProvider;

  beforeEach(() => {
    provider = new TransparencyLogAnchorProvider({
      baseUrl: 'https://rekor.sigstore.dev',
      logName: 'mitch/tlog-v1',
    });
  });

  test('publishRoot returns a valid AnchorRef with entry UUID and timestamp', async () => {
    const ref = await provider.publishRoot(TEST_ROOT, TEST_META);

    expect(typeof ref.ref).toBe('string');
    expect(ref.ref.length).toBeGreaterThan(0);
    expect(ref.timestamp).toBeGreaterThan(0);
  });

  test('publishRoot embeds logName and logIndex metadata', async () => {
    const ref = await provider.publishRoot(TEST_ROOT, TEST_META) as any;

    expect(ref.logName).toBe('mitch/tlog-v1');
    expect(ref.logIndex).toBe(0);
    expect(ref.batchId).toBe('batch-001');
  });

  test('sequential calls increment logIndex (monotonic)', async () => {
    const ref1 = await provider.publishRoot(TEST_ROOT, TEST_META) as any;
    const ref2 = await provider.publishRoot(TEST_ROOT, { batchId: 'batch-002', count: 1 }) as any;

    expect(ref2.logIndex).toBe(ref1.logIndex + 1);
    expect(ref1.ref).not.toBe(ref2.ref); // unique entry UUIDs
  });

  test('integrates with InMemoryAnchorService as drop-in provider', async () => {
    const service = new InMemoryAnchorService(
      { maxBatchSize: 2, maxBatchWindowMs: 100, dedupeWithinBatch: true },
      provider
    );

    const hashA = 'c'.repeat(64) as Hex32;
    const hashB = 'd'.repeat(64) as Hex32;

    const [receiptA] = await Promise.all([
      service.submit({ decisionHash: hashA }),
      service.submit({ decisionHash: hashB }),
    ]);

    expect(receiptA.root).toBeDefined();
    expect(receiptA.includedHashes).toContain(hashA);
  });
});
