/**
 * Durable holder-key custody (Proof-Randomization Increment 2 / C1).
 * Real IndexedDB behaviour via fake-indexeddb: put/get round-trip preserves the
 * non-extractable CryptoKey handle; shred-on-burn deletes one key; whole-pool
 * cleanup deletes by the poolId index.
 */

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair } from '@askmi/shared-crypto';
import {
  putKey,
  getKey,
  deleteKey,
  deletePoolKeys,
  __resetConnectionForTests,
  type StoredHolderKey,
} from '../utils/crypto-db';

async function makeRecord(credentialId: string, poolId: string): Promise<StoredHolderKey> {
  const kp = await generateKeyPair();
  return {
    credentialId,
    poolId,
    publicKeyJwk: await crypto.subtle.exportKey('jwk', kp.publicKey),
    privateKey: kp.privateKey, // non-extractable
    createdAt: Date.now(),
  };
}

beforeEach(async () => {
  // Fresh database per test for isolation.
  __resetConnectionForTests();
  await new Promise<void>((resolve) => {
    const req = indexedDB.deleteDatabase('mitch_holder_keys_v1');
    req.onsuccess = () => resolve();
    req.onerror = () => resolve();
    req.onblocked = () => resolve();
  });
});

describe('crypto-db (holder key custody)', () => {
  it('round-trips a non-extractable private key handle', async () => {
    const rec = await makeRecord('cred-1', 'pool-A');
    await putKey(rec);

    const got = await getKey('cred-1');
    expect(got).toBeDefined();
    expect(got!.poolId).toBe('pool-A');
    // The retrieved handle is still a usable, non-extractable CryptoKey.
    expect(got!.privateKey).toBeInstanceOf(CryptoKey);
    expect(got!.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', got!.privateKey)).rejects.toBeTruthy();
  });

  it('returns undefined for an unknown credential', async () => {
    expect(await getKey('nope')).toBeUndefined();
  });

  it('shred-on-burn deletes a single key', async () => {
    await putKey(await makeRecord('cred-1', 'pool-A'));
    await deleteKey('cred-1');
    expect(await getKey('cred-1')).toBeUndefined();
  });

  it('deletePoolKeys shreds every member of a pool but leaves others', async () => {
    await putKey(await makeRecord('a0', 'pool-A'));
    await putKey(await makeRecord('a1', 'pool-A'));
    await putKey(await makeRecord('b0', 'pool-B'));

    await deletePoolKeys('pool-A');

    expect(await getKey('a0')).toBeUndefined();
    expect(await getKey('a1')).toBeUndefined();
    expect(await getKey('b0')).toBeDefined();
  });
});
