import { describe, test, expect, beforeAll } from 'vitest';
import {
  digestItem,
  verifyMsoDigests,
  extractAndVerifyMso,
} from '../src/mso';
import { encode, encodeEmbeddedCbor, createSign1 } from '../src/index';
import type {
  IssuerSignedItem,
  MobileSecurityObject,
  DigestAlgorithm,
  NameSpace,
} from '../src/mdoc-types';
import { MDL_NAMESPACE, MDL_ELEMENTS } from '../src/mdoc-types';

// ─── Helpers ───────────────────────────────────────────────────────────────

function makeItem(
  digestID: number,
  elementIdentifier: string,
  elementValue: unknown
): IssuerSignedItem {
  return {
    digestID,
    random: crypto.getRandomValues(new Uint8Array(16)),
    elementIdentifier,
    elementValue,
  };
}

async function computeDigest(
  item: IssuerSignedItem,
  alg: AlgorithmIdentifier = 'SHA-256'
): Promise<Uint8Array> {
  const tag24Bytes = encodeEmbeddedCbor(item);
  return new Uint8Array(await crypto.subtle.digest(alg, tag24Bytes));
}

async function buildMso(
  items: IssuerSignedItem[],
  namespace: string = MDL_NAMESPACE,
  alg: DigestAlgorithm = 'SHA-256'
): Promise<MobileSecurityObject> {
  const digestMap = new Map<number, Uint8Array>();
  for (const item of items) {
    digestMap.set(item.digestID, await computeDigest(item, alg));
  }

  return {
    version: '1.0',
    digestAlgorithm: alg,
    valueDigests: new Map([[namespace, digestMap]]),
    deviceKeyInfo: { deviceKey: new Map() },
    docType: 'org.iso.18013.5.1.mDL',
    validityInfo: {
      signed: '2026-01-01T00:00:00Z',
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2027-01-01T00:00:00Z',
    } as unknown as MobileSecurityObject['validityInfo'],
  };
}

// ─── Key Setup ─────────────────────────────────────────────────────────────

let keyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair;

beforeAll(async () => {
  keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify']
  );
  otherKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify']
  );
});

// ─── digestItem ────────────────────────────────────────────────────────────

describe('digestItem', () => {
  test('produces Uint8Array of correct length for SHA-256', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const digest = await digestItem(item, 'SHA-256');
    expect(digest).toBeInstanceOf(Uint8Array);
    expect(digest.length).toBe(32); // SHA-256 = 32 bytes
  });

  test('produces correct length for SHA-384', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const digest = await digestItem(item, 'SHA-384');
    expect(digest.length).toBe(48);
  });

  test('produces correct length for SHA-512', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const digest = await digestItem(item, 'SHA-512');
    expect(digest.length).toBe(64);
  });

  test('same item produces same digest (deterministic)', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const d1 = await digestItem(item, 'SHA-256');
    const d2 = await digestItem(item, 'SHA-256');
    expect(d1).toEqual(d2);
  });

  test('different random produces different digest', async () => {
    const item1 = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const item2 = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    // Different random bytes → different digest
    const d1 = await digestItem(item1, 'SHA-256');
    const d2 = await digestItem(item2, 'SHA-256');
    expect(d1).not.toEqual(d2);
  });

  test('different elementValue produces different digest', async () => {
    const random = crypto.getRandomValues(new Uint8Array(16));
    const item1: IssuerSignedItem = {
      digestID: 0,
      random,
      elementIdentifier: MDL_ELEMENTS.FAMILY_NAME,
      elementValue: 'Müller',
    };
    const item2: IssuerSignedItem = {
      digestID: 0,
      random,
      elementIdentifier: MDL_ELEMENTS.FAMILY_NAME,
      elementValue: 'Schmidt',
    };
    const d1 = await digestItem(item1, 'SHA-256');
    const d2 = await digestItem(item2, 'SHA-256');
    expect(d1).not.toEqual(d2);
  });

  test('rejects unsupported algorithm', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Test');
    await expect(
      digestItem(item, 'SHA-1' as DigestAlgorithm)
    ).rejects.toThrow('Unsupported digest algorithm');
  });
});

// ─── verifyMsoDigests ──────────────────────────────────────────────────────

describe('verifyMsoDigests', () => {
  test('valid: all digests match', async () => {
    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
      makeItem(2, MDL_ELEMENTS.BIRTH_DATE, '1990-05-15'),
    ];
    const mso = await buildMso(items);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, items],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
    expect(result.invalidItems).toBeUndefined();
  });

  test('valid: partial disclosure (subset of MSO items)', async () => {
    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
      makeItem(2, MDL_ELEMENTS.BIRTH_DATE, '1990-05-15'),
    ];
    const mso = await buildMso(items);

    // Only disclose item 1 — selective disclosure
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [items[1]]],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
  });

  test('valid: empty disclosed namespaces', async () => {
    const items = [makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller')];
    const mso = await buildMso(items);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>();

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
  });

  test('valid: empty items array in namespace', async () => {
    const items = [makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller')];
    const mso = await buildMso(items);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, []],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
  });

  test('invalid: tampered elementValue', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const mso = await buildMso([item]);

    // Tamper with the item
    const tampered: IssuerSignedItem = { ...item, elementValue: 'Hacker' };
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [tampered]],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(false);
    expect(result.invalidItems).toHaveLength(1);
    expect(result.invalidItems![0].reason).toContain('Digest mismatch');
    expect(result.invalidItems![0].digestId).toBe(0);
  });

  test('invalid: tampered random bytes', async () => {
    const item = makeItem(0, MDL_ELEMENTS.AGE_OVER_18, true);
    const mso = await buildMso([item]);

    const tampered: IssuerSignedItem = {
      ...item,
      random: crypto.getRandomValues(new Uint8Array(16)),
    };
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [tampered]],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(false);
    expect(result.invalidItems![0].reason).toContain('Digest mismatch');
  });

  test('invalid: digestID not in MSO (fail-closed)', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const mso = await buildMso([item]);

    // Disclose an item with digestID 99 which doesn't exist in MSO
    const unknown = makeItem(99, MDL_ELEMENTS.GIVEN_NAME, 'Fake');
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [unknown]],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(false);
    expect(result.invalidItems![0].reason).toContain('not found in MSO');
    expect(result.invalidItems![0].digestId).toBe(99);
  });

  test('invalid: namespace not in MSO (fail-closed)', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const mso = await buildMso([item]);

    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      ['org.fake.namespace', [item]],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(false);
    expect(result.invalidItems![0].reason).toContain('Namespace');
    expect(result.invalidItems![0].namespace).toBe('org.fake.namespace');
  });

  test('collects multiple invalid items', async () => {
    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
    ];
    const mso = await buildMso(items);

    // Tamper with both
    const tampered = items.map((it) => ({ ...it, elementValue: 'TAMPERED' }));
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, tampered],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(false);
    expect(result.invalidItems!.length).toBe(2);
  });

  test('valid: SHA-384 algorithm', async () => {
    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
    ];
    const mso = await buildMso(items, MDL_NAMESPACE, 'SHA-384');
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, items],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
  });

  test('valid: SHA-512 algorithm', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Test');
    const mso = await buildMso([item], MDL_NAMESPACE, 'SHA-512');
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [item]],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
  });

  test('valid: multiple namespaces', async () => {
    const ns1Items = [makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller')];
    const ns2Items = [makeItem(0, 'custom_field', 'value')];

    const ns1 = MDL_NAMESPACE;
    const ns2 = 'org.custom.namespace';

    // Build MSO with both namespaces
    const digestMap1 = new Map<number, Uint8Array>();
    digestMap1.set(0, await computeDigest(ns1Items[0]));
    const digestMap2 = new Map<number, Uint8Array>();
    digestMap2.set(0, await computeDigest(ns2Items[0]));

    const mso: MobileSecurityObject = {
      version: '1.0',
      digestAlgorithm: 'SHA-256',
      valueDigests: new Map([
        [ns1, digestMap1],
        [ns2, digestMap2],
      ]),
      deviceKeyInfo: { deviceKey: new Map() },
      docType: 'org.iso.18013.5.1.mDL',
      validityInfo: {
        signed: '2026-01-01T00:00:00Z',
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: '2027-01-01T00:00:00Z',
      } as unknown as MobileSecurityObject['validityInfo'],
    };

    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [ns1, ns1Items],
      [ns2, ns2Items],
    ]);

    const result = await verifyMsoDigests(mso, disclosed);
    expect(result.valid).toBe(true);
  });
});

// ─── extractAndVerifyMso ───────────────────────────────────────────────────

describe('extractAndVerifyMso', () => {
  /** Build a CBOR-encodable MSO (plain objects, not Maps — cborg requirement). */
  async function buildSignedMso(
    items: IssuerSignedItem[],
    signingKey: CryptoKey
  ): Promise<Uint8Array> {
    // Build digest map as plain object (cborg can't roundtrip Map reliably)
    const digestObj: Record<number, Uint8Array> = {};
    for (const item of items) {
      digestObj[item.digestID] = await computeDigest(item);
    }
    const msoPlain = {
      version: '1.0',
      digestAlgorithm: 'SHA-256',
      valueDigests: { [MDL_NAMESPACE]: digestObj },
      deviceKeyInfo: { deviceKey: {} },
      docType: 'org.iso.18013.5.1.mDL',
      validityInfo: {
        signed: '2026-01-01T00:00:00Z',
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: '2027-01-01T00:00:00Z',
      },
    };
    const msoBytes = encode(msoPlain);
    return createSign1({ payload: msoBytes, privateKey: signingKey });
  }

  test('valid: signature OK + digests OK', async () => {
    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
    ];
    const issuerAuth = await buildSignedMso(items, keyPair.privateKey);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, items],
    ]);

    const result = await extractAndVerifyMso(
      issuerAuth,
      disclosed,
      keyPair.publicKey
    );
    expect(result.valid).toBe(true);
    expect(result.mso).toBeDefined();
    expect(result.mso!.version).toBe('1.0');
    expect(result.mso!.docType).toBe('org.iso.18013.5.1.mDL');
  });

  test('invalid: wrong signing key', async () => {
    const items = [makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller')];
    const issuerAuth = await buildSignedMso(items, keyPair.privateKey);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, items],
    ]);

    // Verify with different key → signature invalid
    const result = await extractAndVerifyMso(
      issuerAuth,
      disclosed,
      otherKeyPair.publicKey
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('signature invalid');
  });

  test('invalid: signature OK but tampered item', async () => {
    const item = makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller');
    const issuerAuth = await buildSignedMso([item], keyPair.privateKey);

    const tampered: IssuerSignedItem = { ...item, elementValue: 'Hacker' };
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [tampered]],
    ]);

    const result = await extractAndVerifyMso(
      issuerAuth,
      disclosed,
      keyPair.publicKey
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Digest verification failed');
    expect(result.mso).toBeDefined(); // MSO decoded but digests failed
  });

  test('invalid: garbage input', async () => {
    const garbage = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>();

    const result = await extractAndVerifyMso(
      garbage,
      disclosed,
      keyPair.publicKey
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBeDefined();
  });

  test('valid: partial disclosure through E2E', async () => {
    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
      makeItem(2, MDL_ELEMENTS.BIRTH_DATE, '1990-05-15'),
    ];
    const issuerAuth = await buildSignedMso(items, keyPair.privateKey);

    // Only disclose age_over_18
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>([
      [MDL_NAMESPACE, [items[1]]],
    ]);

    const result = await extractAndVerifyMso(
      issuerAuth,
      disclosed,
      keyPair.publicKey
    );
    expect(result.valid).toBe(true);
  });

  test('valid: no items disclosed (empty verification)', async () => {
    const items = [makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Müller')];
    const issuerAuth = await buildSignedMso(items, keyPair.privateKey);
    const disclosed = new Map<NameSpace, IssuerSignedItem[]>();

    const result = await extractAndVerifyMso(
      issuerAuth,
      disclosed,
      keyPair.publicKey
    );
    expect(result.valid).toBe(true);
  });
});
