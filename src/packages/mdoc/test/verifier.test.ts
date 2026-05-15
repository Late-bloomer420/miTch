import { describe, test, expect, beforeAll } from 'vitest';
import { verifyMdocOffline } from '../src/verifier';
import { createSign1 } from '../src/cose';
import { encode, encodeEmbeddedCbor } from '../src/cbor';
import { exportCoseKey } from '../src/cose-key';
import type {
  MdocDocument,
  IssuerSignedItem,
  MobileSecurityObject,
  SessionTranscript,
  ValidityInfo,
} from '../src/mdoc-types';
import { MDL_DOCTYPE, MDL_NAMESPACE, MDL_ELEMENTS } from '../src/mdoc-types';

// ─── Key Setup ──────────────────────────────────────────────────────────────

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

// ─── Helpers ────────────────────────────────────────────────────────────────

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

function makeValidity(overrides?: Partial<Record<string, string>>): ValidityInfo {
  return {
    signed: '2026-01-01T00:00:00Z',
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2027-01-01T00:00:00Z',
    ...overrides,
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
  overrides?: Partial<MobileSecurityObject>
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
    ...overrides,
  };
}

async function signMso(
  mso: MobileSecurityObject,
  privateKey: CryptoKey
): Promise<Uint8Array> {
  return createSign1({ payload: encode(mso), privateKey });
}

async function signDeviceAuth(
  privateKey: CryptoKey,
  sessionTranscript: SessionTranscript
): Promise<Uint8Array> {
  const externalAad = encode(sessionTranscript);
  const payload = encode({ deviceNameSpaces: {} });
  return createSign1({ payload, privateKey, externalAad });
}

async function buildValidDocument(overrides?: {
  docType?: string;
  msoOverrides?: Partial<MobileSecurityObject>;
  tamperItems?: boolean;
  skipDeviceSigned?: boolean;
  wrongDeviceKey?: boolean;
}): Promise<{ document: MdocDocument; items: IssuerSignedItem[] }> {
  const items = [
    makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Mueller'),
    makeItem(1, MDL_ELEMENTS.GIVEN_NAME, 'Erika'),
    makeItem(2, MDL_ELEMENTS.AGE_OVER_18, true),
  ];

  const mso = await buildMso(
    overrides?.tamperItems ? [] : items,
    overrides?.wrongDeviceKey
      ? (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey
      : deviceKeyPair.publicKey,
    overrides?.msoOverrides
  );

  const issuerAuth = await signMso(mso, issuerKeyPair.privateKey);
  const nameSpaces = new Map([[MDL_NAMESPACE, items]]);

  const sessionTranscript = makeSessionTranscript();
  const deviceSignature = await signDeviceAuth(deviceKeyPair.privateKey, sessionTranscript);

  const document: MdocDocument = {
    docType: overrides?.docType ?? MDL_DOCTYPE,
    issuerSigned: { nameSpaces, issuerAuth },
    deviceSigned: overrides?.skipDeviceSigned
      ? undefined
      : { nameSpaces: new Map(), deviceAuth: { deviceSignature } },
  };

  return { document, items };
}

// ─── Full offline verification ──────────────────────────────────────────────

describe('verifyMdocOffline', () => {
  test('valid: complete verification passes all steps', async () => {
    const { document } = await buildValidDocument();
    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(true);
    expect(result.mso).toBeDefined();
    expect(result.steps.length).toBeGreaterThanOrEqual(4);
    for (const step of result.steps) {
      expect(step.valid).toBe(true);
    }
  });

  test('valid: steps include issuer-auth, validity, doctype, device-auth', async () => {
    const { document } = await buildValidDocument();
    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    const stepNames = result.steps.map(s => s.step);
    expect(stepNames).toContain('issuer-auth');
    expect(stepNames).toContain('validity');
    expect(stepNames).toContain('doctype');
    expect(stepNames).toContain('device-auth');
  });

  // ── Issuer auth failures ──────────────────────────────────────────────

  test('fail-closed: wrong issuer key', async () => {
    const { document } = await buildValidDocument();
    const wrongKey = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    );

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: wrongKey.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.steps.find(s => s.step === 'issuer-auth')?.valid).toBe(false);
  });

  test('fail-closed: tampered item digests', async () => {
    const { document } = await buildValidDocument({ tamperItems: true });

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Digest');
  });

  // ── Validity failures ─────────────────────────────────────────────────

  test('fail-closed: expired MSO', async () => {
    const { document } = await buildValidDocument();

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2028-01-01T00:00:00Z'), // after validUntil
    });

    expect(result.valid).toBe(false);
    expect(result.steps.find(s => s.step === 'validity')?.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  test('fail-closed: not-yet-valid MSO', async () => {
    const { document } = await buildValidDocument();

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2025-01-01T00:00:00Z'), // before validFrom
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not yet valid');
  });

  // ── DocType failures ──────────────────────────────────────────────────

  test('fail-closed: docType mismatch', async () => {
    const { document } = await buildValidDocument({
      docType: 'eu.europa.ec.eudi.pid.1', // doesn't match MSO docType
    });

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.steps.find(s => s.step === 'doctype')?.valid).toBe(false);
    expect(result.reason).toContain('mismatch');
  });

  // ── Device auth failures ──────────────────────────────────────────────

  test('fail-closed: missing deviceSigned', async () => {
    const { document } = await buildValidDocument({ skipDeviceSigned: true });

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.steps.find(s => s.step === 'device-auth')?.valid).toBe(false);
    expect(result.reason).toContain('deviceSigned');
  });

  test('fail-closed: wrong session transcript', async () => {
    const { document } = await buildValidDocument();

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: [
        new Uint8Array([0xff, 0xff]), // different transcript
        new Uint8Array([0xff, 0xff]),
        'different-handover',
      ],
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.steps.find(s => s.step === 'device-auth')?.valid).toBe(false);
  });

  test('fail-closed: device key mismatch (MSO has different key)', async () => {
    const { document } = await buildValidDocument({ wrongDeviceKey: true });

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      issuerPublicKey: issuerKeyPair.publicKey,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.steps.find(s => s.step === 'device-auth')?.valid).toBe(false);
  });

  // ── Issuer key from x5chain (no issuerPublicKey provided) ─────────────

  test('fail-closed: no issuerPublicKey and no x5chain', async () => {
    const { document } = await buildValidDocument();

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      // no issuerPublicKey — will try x5chain extraction, which will fail
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Issuer key resolution failed');
  });

  // ── Trust anchor verifier ─────────────────────────────────────────────

  test('fail-closed: trust anchor rejects chain', async () => {
    const { document } = await buildValidDocument();

    const result = await verifyMdocOffline({
      document,
      sessionTranscript: makeSessionTranscript(),
      // no issuerPublicKey — triggers x5chain path, but will fail because no x5chain
      trustAnchorVerifier: async () => false,
      now: new Date('2026-06-15T00:00:00Z'),
    });

    expect(result.valid).toBe(false);
  });
});

// ─── DeviceResponse parser (integration) ────────────────────────────────────

describe('parseDeviceResponse integration', () => {
  test('round-trip: build → encode → parse', async () => {
    const { parseDeviceResponse } = await import('../src/mdoc-parser');

    const items = [
      makeItem(0, MDL_ELEMENTS.FAMILY_NAME, 'Mueller'),
      makeItem(1, MDL_ELEMENTS.AGE_OVER_18, true),
    ];

    const mso = await buildMso(items, deviceKeyPair.publicKey);
    const issuerAuth = await signMso(mso, issuerKeyPair.privateKey);

    const deviceResponse = {
      version: '1.0',
      status: 0,
      documents: [{
        docType: MDL_DOCTYPE,
        issuerSigned: {
          nameSpaces: new Map([[MDL_NAMESPACE, items]]),
          issuerAuth,
        },
        deviceSigned: {
          nameSpaces: new Map(),
          deviceAuth: {
            deviceSignature: await signDeviceAuth(
              deviceKeyPair.privateKey,
              makeSessionTranscript()
            ),
          },
        },
      }],
    };

    const encoded = encode(deviceResponse);
    const parsed = parseDeviceResponse(encoded);

    expect(parsed.version).toBe('1.0');
    expect(parsed.status).toBe(0);
    expect(parsed.documents).toHaveLength(1);
    expect(parsed.documents[0].docType).toBe(MDL_DOCTYPE);
  });
});
