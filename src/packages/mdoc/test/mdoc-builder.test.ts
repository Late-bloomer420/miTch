/**
 * Tests for mdoc document builder (issuance pipeline).
 *
 * Verifies: item construction, digest correctness, MSO assembly,
 * COSE_Sign1 signing, and full build→verify roundtrip.
 */

import { describe, test, expect, beforeAll } from 'vitest';
import {
  buildIssuerSignedItems,
  buildMobileSecurityObject,
  signMobileSecurityObject,
  buildMdocDocument,
} from '../src/mdoc-builder';
import { verifyMdocOffline } from '../src/verifier';
import { verifySign1 } from '../src/cose';
import { decode, decodeMdoc } from '../src/cbor';
import { digestItem } from '../src/mso';
import { createSign1, encode } from '../src/index';
import { MDL_DOCTYPE, MDL_NAMESPACE, MDL_ELEMENTS } from '../src/mdoc-types';
import type { ValidityInfo, SessionTranscript } from '../src/mdoc-types';

// ─── Key Setup ───────────────────────────────────────────────────────

let issuerKeyPair: CryptoKeyPair;
let deviceKeyPair: CryptoKeyPair;

beforeAll(async () => {
  issuerKeyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  deviceKeyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
});

function makeValidity(): ValidityInfo {
  return {
    signed: '2026-01-01T00:00:00Z',
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2027-01-01T00:00:00Z',
  } as unknown as ValidityInfo;
}

function makeSessionTranscript(): SessionTranscript {
  return [new Uint8Array([0x01, 0x02, 0x03]), new Uint8Array([0x04, 0x05, 0x06]), 'handover-data'];
}

// ─── buildIssuerSignedItems ──────────────────────────────────────────

describe('buildIssuerSignedItems', () => {
  test('creates items with sequential digestIDs and random salts', () => {
    const items = buildIssuerSignedItems({
      family_name: 'Mueller',
      given_name: 'Erika',
      age_over_18: true,
    });

    expect(items).toHaveLength(3);
    expect(items[0].digestID).toBe(0);
    expect(items[1].digestID).toBe(1);
    expect(items[2].digestID).toBe(2);
    expect(items[0].elementIdentifier).toBe('family_name');
    expect(items[0].elementValue).toBe('Mueller');
    expect(items[0].random).toBeInstanceOf(Uint8Array);
    expect(items[0].random.length).toBe(16);
  });

  test('respects startDigestID offset', () => {
    const items = buildIssuerSignedItems({ foo: 'bar' }, 10);
    expect(items[0].digestID).toBe(10);
  });

  test('each item gets unique random salt', () => {
    const items = buildIssuerSignedItems({ a: 1, b: 2, c: 3 });
    const salts = items.map((i) => Array.from(i.random).join(','));
    const unique = new Set(salts);
    expect(unique.size).toBe(3);
  });
});

// ─── buildMobileSecurityObject ───────────────────────────────────────

describe('buildMobileSecurityObject', () => {
  test('produces MSO with correct valueDigests', async () => {
    const items = buildIssuerSignedItems({
      [MDL_ELEMENTS.FAMILY_NAME]: 'Mueller',
      [MDL_ELEMENTS.AGE_OVER_18]: true,
    });

    const mso = await buildMobileSecurityObject({
      docType: MDL_DOCTYPE,
      nameSpaceItems: new Map([[MDL_NAMESPACE, items]]),
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    expect(mso.docType).toBe(MDL_DOCTYPE);
    expect(mso.version).toBe('1.0');
    expect(mso.digestAlgorithm).toBe('SHA-256');
    expect(mso.valueDigests.has(MDL_NAMESPACE)).toBe(true);

    const digestMap = mso.valueDigests.get(MDL_NAMESPACE)!;
    expect(digestMap.size).toBe(2);

    // Verify digests match item hashes
    for (const item of items) {
      const expected = await digestItem(item, 'SHA-256');
      const actual = digestMap.get(item.digestID)!;
      expect(actual).toEqual(expected);
    }
  });

  test('supports multiple namespaces', async () => {
    const ns1Items = buildIssuerSignedItems({ a: 1 }, 0);
    const ns2Items = buildIssuerSignedItems({ b: 2 }, 1);

    const mso = await buildMobileSecurityObject({
      docType: 'test.docType',
      nameSpaceItems: new Map([
        ['ns.one', ns1Items],
        ['ns.two', ns2Items],
      ]),
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    expect(mso.valueDigests.size).toBe(2);
    expect(mso.valueDigests.has('ns.one')).toBe(true);
    expect(mso.valueDigests.has('ns.two')).toBe(true);
  });
});

// ─── signMobileSecurityObject ────────────────────────────────────────

describe('signMobileSecurityObject', () => {
  test('produces verifiable COSE_Sign1 bytes', async () => {
    const items = buildIssuerSignedItems({ test: 'value' });
    const mso = await buildMobileSecurityObject({
      docType: MDL_DOCTYPE,
      nameSpaceItems: new Map([[MDL_NAMESPACE, items]]),
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    const issuerAuth = await signMobileSecurityObject(mso, issuerKeyPair.privateKey);
    expect(issuerAuth).toBeInstanceOf(Uint8Array);
    expect(issuerAuth.length).toBeGreaterThan(0);

    // Verify the COSE_Sign1 signature
    const result = await verifySign1(issuerAuth, issuerKeyPair.publicKey);
    expect(result.valid).toBe(true);
  });

  test('signed MSO payload decodes back to original', async () => {
    const items = buildIssuerSignedItems({ test: 42 });
    const mso = await buildMobileSecurityObject({
      docType: 'test.dt',
      nameSpaceItems: new Map([['test.ns', items]]),
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    const issuerAuth = await signMobileSecurityObject(mso, issuerKeyPair.privateKey);
    const result = await verifySign1(issuerAuth, issuerKeyPair.publicKey);
    const decoded = decodeMdoc<Map<string, unknown>>(result.payload);

    expect(decoded.get('docType')).toBe('test.dt');
    expect(decoded.get('version')).toBe('1.0');
    expect(decoded.get('digestAlgorithm')).toBe('SHA-256');
  });
});

// ─── buildMdocDocument ───────────────────────────────────────────────

describe('buildMdocDocument', () => {
  test('builds a complete mdoc document', async () => {
    const result = await buildMdocDocument({
      docType: MDL_DOCTYPE,
      nameSpaces: {
        [MDL_NAMESPACE]: {
          [MDL_ELEMENTS.FAMILY_NAME]: 'Mueller',
          [MDL_ELEMENTS.GIVEN_NAME]: 'Erika',
          [MDL_ELEMENTS.AGE_OVER_18]: true,
        },
      },
      issuerPrivateKey: issuerKeyPair.privateKey,
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    expect(result.document.docType).toBe(MDL_DOCTYPE);
    expect(result.document.issuerSigned.nameSpaces.has(MDL_NAMESPACE)).toBe(true);
    expect(result.document.issuerSigned.issuerAuth).toBeInstanceOf(Uint8Array);
    expect(result.document.deviceSigned).toBeUndefined();
    expect(result.documentCbor).toBeInstanceOf(Uint8Array);
    expect(result.mso.docType).toBe(MDL_DOCTYPE);
  });

  test('document has no deviceSigned (added at presentation)', async () => {
    const result = await buildMdocDocument({
      docType: MDL_DOCTYPE,
      nameSpaces: { [MDL_NAMESPACE]: { test: 'value' } },
      issuerPrivateKey: issuerKeyPair.privateKey,
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    expect(result.document.deviceSigned).toBeUndefined();
  });

  test('CBOR bytes are non-empty and decodable', async () => {
    const result = await buildMdocDocument({
      docType: MDL_DOCTYPE,
      nameSpaces: { [MDL_NAMESPACE]: { test: 123 } },
      issuerPrivateKey: issuerKeyPair.privateKey,
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    expect(result.documentCbor.length).toBeGreaterThan(0);
    const decoded = decode<Record<string, unknown>>(result.documentCbor);
    expect(decoded.docType).toBe(MDL_DOCTYPE);
  });
});

// ─── Build → Verify Roundtrip ────────────────────────────────────────

describe('buildMdocDocument → verifyMdocOffline roundtrip', () => {
  test('issued document passes full offline verification (with device auth)', async () => {
    const result = await buildMdocDocument({
      docType: MDL_DOCTYPE,
      nameSpaces: {
        [MDL_NAMESPACE]: {
          [MDL_ELEMENTS.FAMILY_NAME]: 'Mueller',
          [MDL_ELEMENTS.GIVEN_NAME]: 'Erika',
          [MDL_ELEMENTS.AGE_OVER_18]: true,
          [MDL_ELEMENTS.ISSUING_COUNTRY]: 'DE',
        },
      },
      issuerPrivateKey: issuerKeyPair.privateKey,
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    // Simulate holder adding deviceSigned at presentation time
    const sessionTranscript = makeSessionTranscript();
    const deviceSignature = await createSign1({
      payload: encode({ deviceNameSpaces: {} }),
      privateKey: deviceKeyPair.privateKey,
      externalAad: encode(sessionTranscript),
    });

    const documentWithDeviceAuth = {
      ...result.document,
      deviceSigned: {
        nameSpaces: new Map(),
        deviceAuth: { deviceSignature },
      },
    };

    const verification = await verifyMdocOffline({
      document: documentWithDeviceAuth,
      sessionTranscript,
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(verification.valid).toBe(true);
    expect(verification.steps.length).toBeGreaterThanOrEqual(4);
    for (const step of verification.steps) {
      expect(step.valid).toBe(true);
    }
  });

  test('issued document fails verification with wrong issuer key', async () => {
    const result = await buildMdocDocument({
      docType: MDL_DOCTYPE,
      nameSpaces: { [MDL_NAMESPACE]: { test: 'value' } },
      issuerPrivateKey: issuerKeyPair.privateKey,
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    const sessionTranscript = makeSessionTranscript();
    const deviceSignature = await createSign1({
      payload: encode({ deviceNameSpaces: {} }),
      privateKey: deviceKeyPair.privateKey,
      externalAad: encode(sessionTranscript),
    });

    const doc = {
      ...result.document,
      deviceSigned: {
        nameSpaces: new Map(),
        deviceAuth: { deviceSignature },
      },
    };

    const wrongKey = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );

    const verification = await verifyMdocOffline({
      document: doc,
      sessionTranscript,
      issuerPublicKey: wrongKey.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(verification.valid).toBe(false);
  });

  test('issued document without deviceSigned fails verification (fail-closed)', async () => {
    const result = await buildMdocDocument({
      docType: MDL_DOCTYPE,
      nameSpaces: { [MDL_NAMESPACE]: { test: 'value' } },
      issuerPrivateKey: issuerKeyPair.privateKey,
      devicePublicKey: deviceKeyPair.publicKey,
      validityInfo: makeValidity(),
    });

    const verification = await verifyMdocOffline({
      document: result.document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(verification.valid).toBe(false);
    expect(verification.steps.some((s) => s.step === 'device-auth' && !s.valid)).toBe(true);
  });
});
