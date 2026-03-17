import { describe, test, expect, beforeAll } from 'vitest';
import { importCoseKey, exportCoseKey, COSE_KEY } from '../src/cose-key';
import { createSign1, verifySign1 } from '../src/cose';
import { encode } from '../src/cbor';

// ─── Test Key Setup ─────────────────────────────────────────────────────────

let keyPair: CryptoKeyPair;

beforeAll(async () => {
  keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable for export tests
    ['sign', 'verify'],
  );
});

// ─── Constants ──────────────────────────────────────────────────────────────

describe('COSE_KEY constants', () => {
  test('KTY = 1', () => expect(COSE_KEY.KTY).toBe(1));
  test('ALG = 3', () => expect(COSE_KEY.ALG).toBe(3));
  test('CRV = -1', () => expect(COSE_KEY.CRV).toBe(-1));
  test('X = -2', () => expect(COSE_KEY.X).toBe(-2));
  test('Y = -3', () => expect(COSE_KEY.Y).toBe(-3));
  test('KTY_EC2 = 2', () => expect(COSE_KEY.KTY_EC2).toBe(2));
  test('CRV_P256 = 1', () => expect(COSE_KEY.CRV_P256).toBe(1));
});

// ─── Roundtrip Tests ────────────────────────────────────────────────────────

describe('COSE_Key roundtrip (export → import)', () => {
  test('roundtrip: export then import produces working verify key', async () => {
    const coseKey = await exportCoseKey(keyPair.publicKey);
    const imported = await importCoseKey(coseKey);

    // Sign with original private key, verify with imported public key
    const payload = encode({ test: 'roundtrip' });
    const signed = await createSign1({ payload, privateKey: keyPair.privateKey });
    const result = await verifySign1(signed, imported);
    expect(result.valid).toBe(true);
  });

  test('exported COSE_Key has correct structure', async () => {
    const coseKey = await exportCoseKey(keyPair.publicKey);

    expect(coseKey).toBeInstanceOf(Map);
    expect(coseKey.get(COSE_KEY.KTY)).toBe(COSE_KEY.KTY_EC2);
    expect(coseKey.get(COSE_KEY.CRV)).toBe(COSE_KEY.CRV_P256);

    const x = coseKey.get(COSE_KEY.X) as Uint8Array;
    const y = coseKey.get(COSE_KEY.Y) as Uint8Array;
    expect(x).toBeInstanceOf(Uint8Array);
    expect(y).toBeInstanceOf(Uint8Array);
    expect(x.length).toBe(32);
    expect(y.length).toBe(32);
  });
});

// ─── Import from Map ────────────────────────────────────────────────────────

describe('importCoseKey from Map', () => {
  test('import from Map works', async () => {
    const coseKey = await exportCoseKey(keyPair.publicKey);
    // coseKey is already a Map
    const imported = await importCoseKey(coseKey);
    expect(imported).toBeDefined();
    expect(imported.type).toBe('public');
  });
});

// ─── Import from plain object ──────────────────────────────────────────────

describe('importCoseKey from plain object (CBOR-decoded)', () => {
  test('import from plain object works', async () => {
    const coseKey = await exportCoseKey(keyPair.publicKey);

    // Simulate CBOR decode result: plain object with numeric keys
    const plainObj: Record<number, unknown> = {};
    for (const [k, v] of coseKey) {
      plainObj[k] = v;
    }

    const imported = await importCoseKey(plainObj);
    expect(imported).toBeDefined();
    expect(imported.type).toBe('public');

    // Verify it works for signature verification
    const payload = encode({ test: 'plain-obj' });
    const signed = await createSign1({ payload, privateKey: keyPair.privateKey });
    const result = await verifySign1(signed, imported);
    expect(result.valid).toBe(true);
  });
});

// ─── Rejection Tests ────────────────────────────────────────────────────────

describe('importCoseKey rejection (fail-closed)', () => {
  test('rejects unsupported key type (not EC2)', async () => {
    const badKey = new Map<number, unknown>();
    badKey.set(COSE_KEY.KTY, 4); // OKP, not EC2
    badKey.set(COSE_KEY.CRV, COSE_KEY.CRV_P256);
    badKey.set(COSE_KEY.X, new Uint8Array(32));
    badKey.set(COSE_KEY.Y, new Uint8Array(32));

    await expect(importCoseKey(badKey)).rejects.toThrow('Unsupported COSE_Key type');
  });

  test('rejects unsupported curve (not P-256)', async () => {
    const badKey = new Map<number, unknown>();
    badKey.set(COSE_KEY.KTY, COSE_KEY.KTY_EC2);
    badKey.set(COSE_KEY.CRV, 2); // P-384, not P-256
    badKey.set(COSE_KEY.X, new Uint8Array(32));
    badKey.set(COSE_KEY.Y, new Uint8Array(32));

    await expect(importCoseKey(badKey)).rejects.toThrow('Unsupported COSE_Key curve');
  });

  test('rejects missing x coordinate', async () => {
    const badKey = new Map<number, unknown>();
    badKey.set(COSE_KEY.KTY, COSE_KEY.KTY_EC2);
    badKey.set(COSE_KEY.CRV, COSE_KEY.CRV_P256);
    badKey.set(COSE_KEY.Y, new Uint8Array(32));

    await expect(importCoseKey(badKey)).rejects.toThrow('missing x or y');
  });

  test('rejects missing y coordinate', async () => {
    const badKey = new Map<number, unknown>();
    badKey.set(COSE_KEY.KTY, COSE_KEY.KTY_EC2);
    badKey.set(COSE_KEY.CRV, COSE_KEY.CRV_P256);
    badKey.set(COSE_KEY.X, new Uint8Array(32));

    await expect(importCoseKey(badKey)).rejects.toThrow('missing x or y');
  });

  test('rejects wrong coordinate length', async () => {
    const badKey = new Map<number, unknown>();
    badKey.set(COSE_KEY.KTY, COSE_KEY.KTY_EC2);
    badKey.set(COSE_KEY.CRV, COSE_KEY.CRV_P256);
    badKey.set(COSE_KEY.X, new Uint8Array(16)); // wrong length
    badKey.set(COSE_KEY.Y, new Uint8Array(32));

    await expect(importCoseKey(badKey)).rejects.toThrow('Invalid P-256 coordinate length');
  });
});
