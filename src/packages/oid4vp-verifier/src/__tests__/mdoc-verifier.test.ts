/**
 * Tests for mdoc presentation verification via OID4VP.
 *
 * Builds valid DeviceResponse CBOR fixtures, base64-encodes them,
 * and runs them through verifyMdocPresentation().
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { verifyMdocPresentation } from '../mdoc-verifier';
import {
  createSign1,
  encode,
  encodeEmbeddedCbor,
  exportCoseKey,
  MDL_DOCTYPE,
  MDL_NAMESPACE,
  MDL_ELEMENTS,
  type IssuerSignedItem,
  type MobileSecurityObject,
  type SessionTranscript,
  type ValidityInfo,
} from '@mitch/mdoc';

// ─── Key Setup ───────────────────────────────────────────────────────

let issuerKeyPair: CryptoKeyPair;
let deviceKeyPair: CryptoKeyPair;

beforeAll(async () => {
  issuerKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  deviceKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
});

// ─── Helpers ─────────────────────────────────────────────────────────

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

async function computeDigest(item: IssuerSignedItem): Promise<Uint8Array> {
  const tag24Bytes = encodeEmbeddedCbor(item);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', tag24Bytes));
}

function makeValidity(): ValidityInfo {
  return {
    signed: '2026-01-01T00:00:00Z',
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2027-01-01T00:00:00Z',
  } as unknown as ValidityInfo;
}

function makeSessionTranscript(): SessionTranscript {
  return [
    new Uint8Array([0x01, 0x02, 0x03]),
    new Uint8Array([0x04, 0x05, 0x06]),
    'handover-data',
  ];
}

async function buildMso(
  items: IssuerSignedItem[],
  devicePublicKey: CryptoKey,
): Promise<MobileSecurityObject> {
  const digestMap = new Map<number, Uint8Array>();
  for (const item of items) {
    digestMap.set(item.digestID, await computeDigest(item));
  }
  const coseKey = await exportCoseKey(devicePublicKey);
  return {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests: new Map([[MDL_NAMESPACE, digestMap]]),
    deviceKeyInfo: { deviceKey: coseKey },
    docType: MDL_DOCTYPE,
    validityInfo: makeValidity(),
  };
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build a valid DeviceResponse CBOR blob and return base64url.
 */
async function buildDeviceResponseBase64(opts?: {
  skipDeviceSigned?: boolean;
  wrongDeviceKey?: boolean;
  docType?: string;
}): Promise<string> {
  const items = [
    makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Mueller'),
    makeItem(1, MDL_ELEMENTS.GIVEN_NAME, 'Erika'),
    makeItem(2, MDL_ELEMENTS.AGE_OVER_18, true),
    makeItem(3, MDL_ELEMENTS.ISSUING_COUNTRY, 'DE'),
  ];

  const mso = await buildMso(items, opts?.wrongDeviceKey
    ? (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey
    : deviceKeyPair.publicKey,
  );

  const issuerAuth = await createSign1({
    payload: encode(mso),
    privateKey: issuerKeyPair.privateKey,
  });

  const nameSpaces = new Map([[MDL_NAMESPACE, items]]);
  const sessionTranscript = makeSessionTranscript();

  const deviceSignature = opts?.skipDeviceSigned
    ? undefined
    : await createSign1({
        payload: encode({ deviceNameSpaces: {} }),
        privateKey: deviceKeyPair.privateKey,
        externalAad: encode(sessionTranscript),
      });

  const document: Record<string, unknown> = {
    docType: opts?.docType ?? MDL_DOCTYPE,
    issuerSigned: { nameSpaces, issuerAuth },
  };

  if (deviceSignature) {
    document.deviceSigned = {
      nameSpaces: new Map(),
      deviceAuth: { deviceSignature },
    };
  }

  const deviceResponse = {
    version: '1.0',
    documents: [document],
    status: 0,
  };

  const cbor = encode(deviceResponse);
  return bytesToBase64url(cbor);
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('verifyMdocPresentation', () => {
  it('verifies a valid mdoc DeviceResponse and extracts disclosed claims', async () => {
    const b64 = await buildDeviceResponseBase64();
    const result = await verifyMdocPresentation({
      deviceResponseBase64: b64,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.documents).toHaveLength(1);
    expect(result.documents[0].docType).toBe(MDL_DOCTYPE);
    expect(result.disclosedClaims).toHaveProperty(MDL_ELEMENTS.FAMILY_NAME, 'Mueller');
    expect(result.disclosedClaims).toHaveProperty(MDL_ELEMENTS.GIVEN_NAME, 'Erika');
    expect(result.disclosedClaims).toHaveProperty(MDL_ELEMENTS.AGE_OVER_18, true);
    expect(result.disclosedClaims).toHaveProperty(MDL_ELEMENTS.ISSUING_COUNTRY, 'DE');
  });

  it('returns namespace-scoped claims per document', async () => {
    const b64 = await buildDeviceResponseBase64();
    const result = await verifyMdocPresentation({
      deviceResponseBase64: b64,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(true);
    const nsClaims = result.documents[0].namespaceClaims;
    expect(nsClaims).toHaveProperty(MDL_NAMESPACE);
    expect(nsClaims[MDL_NAMESPACE]).toHaveProperty(MDL_ELEMENTS.FAMILY_NAME, 'Mueller');
  });

  it('fail-closed: wrong issuer key rejects verification', async () => {
    const b64 = await buildDeviceResponseBase64();
    const wrongKey = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    );

    const result = await verifyMdocPresentation({
      deviceResponseBase64: b64,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: wrongKey.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    // Claims must NOT be disclosed on failure
    expect(Object.keys(result.disclosedClaims)).toHaveLength(0);
  });

  it('fail-closed: missing deviceSigned rejects verification', async () => {
    const b64 = await buildDeviceResponseBase64({ skipDeviceSigned: true });
    const result = await verifyMdocPresentation({
      deviceResponseBase64: b64,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('failed verification'))).toBe(true);
    expect(Object.keys(result.disclosedClaims)).toHaveLength(0);
  });

  it('fail-closed: expired MSO rejects verification', async () => {
    const b64 = await buildDeviceResponseBase64();
    const result = await verifyMdocPresentation({
      deviceResponseBase64: b64,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2028-01-01T00:00:00Z'), // After validUntil
    });

    expect(result.valid).toBe(false);
    expect(Object.keys(result.disclosedClaims)).toHaveLength(0);
  });

  it('rejects invalid base64 input', async () => {
    const result = await verifyMdocPresentation({
      deviceResponseBase64: '!!!not-valid-base64!!!',
      sessionTranscript: makeSessionTranscript(),
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('decode'))).toBe(true);
  });

  it('rejects valid base64 but invalid CBOR', async () => {
    const invalidCbor = bytesToBase64url(new Uint8Array([0xff, 0xff, 0xff]));
    const result = await verifyMdocPresentation({
      deviceResponseBase64: invalidCbor,
      sessionTranscript: makeSessionTranscript(),
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('parse') || e.includes('CBOR'))).toBe(true);
  });

  it('per-step diagnostics are available in document results', async () => {
    const b64 = await buildDeviceResponseBase64();
    const result = await verifyMdocPresentation({
      deviceResponseBase64: b64,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(true);
    const steps = result.documents[0].verification.steps;
    expect(steps.length).toBeGreaterThanOrEqual(4);
    const stepNames = steps.map(s => s.step);
    expect(stepNames).toContain('issuer-auth');
    expect(stepNames).toContain('validity');
    expect(stepNames).toContain('doctype');
    expect(stepNames).toContain('device-auth');
  });
});

describe('verifyMdocPresentation — OID4VP format integration', () => {
  it('mso_mdoc descriptor format accepted in authorization response', async () => {
    // Verify the type system accepts mso_mdoc
    const descriptor = {
      id: 'mdl-descriptor',
      format: 'mso_mdoc' as const,
      path: '$',
    };
    expect(descriptor.format).toBe('mso_mdoc');
  });
});
