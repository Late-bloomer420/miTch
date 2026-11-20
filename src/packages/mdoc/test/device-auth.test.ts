import { describe, test, expect, beforeAll } from 'vitest';
import {
  verifyDeviceSignature,
  verifyDeviceMac,
  verifyDeviceAuth,
  buildDeviceAuthenticationBytes,
} from '../src/device-auth';
import { exportCoseKey } from '../src/cose-key';
import { createSign1, createMac0, deriveSessionMacKey, decodeCoseSign1 } from '../src/cose';
import { encode, decode } from '../src/cbor';
import type {
  DeviceAuth,
  MobileSecurityObject,
  SessionTranscript,
} from '../src/mdoc-types';

// ─── Test Key Setup ─────────────────────────────────────────────────────────

let deviceKeyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair;
let deviceEcdhKeyPair: CryptoKeyPair;
let readerEcdhKeyPair: CryptoKeyPair;

beforeAll(async () => {
  deviceKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  otherKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  // ECDH key pairs for Mac0 path
  deviceEcdhKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey'],
  );
  readerEcdhKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey'],
  );
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeSessionTranscript(): SessionTranscript {
  return [
    new Uint8Array([0x01, 0x02, 0x03]), // deviceEngagementBytes
    new Uint8Array([0x04, 0x05, 0x06]), // eReaderKeyBytes
    'handover-data',                     // handover
  ];
}

const DOCTYPE = 'org.iso.18013.5.1.mDL';

/** ISO/IEC 18013-5 §9.1.3.6: detached COSE_Sign1 over DeviceAuthenticationBytes, empty AAD. */
async function signDeviceAuth(
  privateKey: CryptoKey,
  sessionTranscript: SessionTranscript,
  docType = DOCTYPE,
): Promise<Uint8Array> {
  return createSign1({
    payload: buildDeviceAuthenticationBytes(sessionTranscript, docType),
    privateKey,
    detachedPayload: true,
  });
}

/** Pre-fix shape: embedded payload + SessionTranscript as external_aad (non-ISO). */
async function signLegacyDeviceAuth(
  privateKey: CryptoKey,
  sessionTranscript: SessionTranscript,
): Promise<Uint8Array> {
  return createSign1({
    payload: encode({ deviceNameSpaces: {} }),
    privateKey,
    externalAad: encode(sessionTranscript),
  });
}

async function buildMsoWithDeviceKey(publicKey: CryptoKey): Promise<MobileSecurityObject> {
  const coseKey = await exportCoseKey(publicKey);
  return {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests: new Map(),
    deviceKeyInfo: { deviceKey: coseKey },
    docType: 'org.iso.18013.5.1.mDL',
    validityInfo: {
      signed: new Date('2025-01-01'),
      validFrom: new Date('2025-01-01'),
      validUntil: new Date('2026-01-01'),
    },
  };
}

async function buildMsoWithEcdhDeviceKey(publicKey: CryptoKey): Promise<MobileSecurityObject> {
  // Export ECDH public key as JWK then build a COSE_Key map manually
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  const coseKey = new Map<number, unknown>();
  coseKey.set(1, 2); // kty: EC2
  coseKey.set(-1, 1); // crv: P-256
  coseKey.set(-2, base64urlToUint8Array(jwk.x!)); // x
  coseKey.set(-3, base64urlToUint8Array(jwk.y!)); // y
  return {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests: new Map(),
    deviceKeyInfo: { deviceKey: coseKey },
    docType: 'org.iso.18013.5.1.mDL',
    validityInfo: {
      signed: new Date('2025-01-01'),
      validFrom: new Date('2025-01-01'),
      validUntil: new Date('2026-01-01'),
    },
  };
}

function base64urlToUint8Array(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function macDeviceAuth(
  macKey: CryptoKey,
  sessionTranscript: SessionTranscript,
): Promise<Uint8Array> {
  return createMac0({
    payload: buildDeviceAuthenticationBytes(sessionTranscript, DOCTYPE),
    macKey,
    detachedPayload: true,
  });
}

// ─── verifyDeviceSignature ──────────────────────────────────────────────────

describe('verifyDeviceSignature', () => {
  test('valid: correct key + SessionTranscript', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const result = await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript, DOCTYPE);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  test('invalid: wrong device key', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const result = await verifyDeviceSignature(sig, otherKeyPair.publicKey, transcript, DOCTYPE);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('invalid');
  });

  test('invalid: tampered SessionTranscript', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const tamperedTranscript: SessionTranscript = [
      new Uint8Array([0xff, 0xfe, 0xfd]), // different engagement
      transcript[1],
      transcript[2],
    ];

    const result = await verifyDeviceSignature(sig, deviceKeyPair.publicKey, tamperedTranscript, DOCTYPE);
    expect(result.valid).toBe(false);
  });

  test('invalid: corrupted signature bytes', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    // Corrupt the bytes
    const corrupted = new Uint8Array(sig);
    corrupted[corrupted.length - 1] ^= 0xff;

    const result = await verifyDeviceSignature(corrupted, deviceKeyPair.publicKey, transcript, DOCTYPE);
    expect(result.valid).toBe(false);
  });

  test('null SessionTranscript fields accepted', async () => {
    const transcript: SessionTranscript = [null, null, 'handover'];
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const result = await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript, DOCTYPE);
    expect(result.valid).toBe(true);
  });

  test('invalid: garbage bytes', async () => {
    const transcript = makeSessionTranscript();
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03]);

    const result = await verifyDeviceSignature(garbage, deviceKeyPair.publicKey, transcript, DOCTYPE);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('decoding failed');
  });
});

// ─── verifyDeviceAuth (E2E) ─────────────────────────────────────────────────

describe('verifyDeviceAuth', () => {
  test('valid: full E2E with MSO device key', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    const mso = await buildMsoWithDeviceKey(deviceKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceSignature: sig };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(true);
  });

  test('invalid: MSO device key does not match signer', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    // MSO has OTHER key, not the signer's key
    const mso = await buildMsoWithDeviceKey(otherKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceSignature: sig };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(false);
  });

  test('invalid: no deviceSignature', async () => {
    const transcript = makeSessionTranscript();
    const mso = await buildMsoWithDeviceKey(deviceKeyPair.publicKey);
    const deviceAuth: DeviceAuth = {};

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('No deviceSignature');
  });

  test('invalid: deviceMac without eReaderPrivateKey', async () => {
    const transcript = makeSessionTranscript();
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);
    const mso = await buildMsoWithEcdhDeviceKey(deviceEcdhKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceMac: mac };

    // No eReaderPrivateKey → should fail
    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('eReaderPrivateKey');
  });

  test('invalid: missing deviceKeyInfo in MSO', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    const mso = await buildMsoWithDeviceKey(deviceKeyPair.publicKey);
    // Remove deviceKeyInfo
    (mso as any).deviceKeyInfo = undefined;
    const deviceAuth: DeviceAuth = { deviceSignature: sig };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('missing deviceKeyInfo');
  });

  test('invalid: bad COSE_Key in MSO', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    const mso = await buildMsoWithDeviceKey(deviceKeyPair.publicKey);
    // Corrupt the device key: set unsupported kty
    mso.deviceKeyInfo.deviceKey.set(1, 99);
    const deviceAuth: DeviceAuth = { deviceSignature: sig };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Device key import failed');
  });
});

// ─── verifyDeviceMac ───────────────────────────────────────────────────────

describe('verifyDeviceMac', () => {
  test('valid: correct MAC key + SessionTranscript', async () => {
    const transcript = makeSessionTranscript();
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);

    const result = await verifyDeviceMac(mac, macKey, transcript, DOCTYPE);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  test('invalid: wrong MAC key', async () => {
    const transcript = makeSessionTranscript();
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);

    // Derive a different key (device↔device instead of reader↔device)
    const wrongKey = await deriveSessionMacKey(deviceEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const result = await verifyDeviceMac(mac, wrongKey, transcript, DOCTYPE);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('MAC tag invalid');
  });

  test('invalid: tampered SessionTranscript', async () => {
    const transcript = makeSessionTranscript();
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);

    const tamperedTranscript: SessionTranscript = [
      new Uint8Array([0xff, 0xfe]),
      transcript[1],
      transcript[2],
    ];
    const result = await verifyDeviceMac(mac, macKey, tamperedTranscript, DOCTYPE);
    expect(result.valid).toBe(false);
  });

  test('invalid: garbage bytes', async () => {
    const transcript = makeSessionTranscript();
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);

    const result = await verifyDeviceMac(new Uint8Array([0x00, 0x01]), macKey, transcript, DOCTYPE);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('decoding failed');
  });
});

// ─── verifyDeviceAuth with Mac0 (E2E) ──────────────────────────────────────

describe('verifyDeviceAuth (Mac0 path)', () => {
  test('valid: full E2E ECDH → MAC key → createMac0 → verifyDeviceAuth', async () => {
    const transcript = makeSessionTranscript();

    // Both sides derive the same MAC key (reader side)
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);
    const mso = await buildMsoWithEcdhDeviceKey(deviceEcdhKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceMac: mac };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript, readerEcdhKeyPair.privateKey);
    expect(result.valid).toBe(true);
  });

  test('invalid: wrong reader key (key agreement mismatch)', async () => {
    const transcript = makeSessionTranscript();

    // MAC was created with reader↔device key agreement
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);
    const mso = await buildMsoWithEcdhDeviceKey(deviceEcdhKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceMac: mac };

    // Generate a different reader key — key agreement will produce different MAC key
    const wrongReader = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits', 'deriveKey'],
    );
    const result = await verifyDeviceAuth(deviceAuth, mso, transcript, wrongReader.privateKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('MAC tag invalid');
  });

  test('deviceSignature takes priority over deviceMac', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    const macKey = await deriveSessionMacKey(readerEcdhKeyPair.privateKey, deviceEcdhKeyPair.publicKey);
    const mac = await macDeviceAuth(macKey, transcript);

    // Both present — ECDSA key in MSO, so deviceSignature path is used
    const mso = await buildMsoWithDeviceKey(deviceKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceSignature: sig, deviceMac: mac };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(true);
  });

  test('invalid: no deviceSignature or deviceMac', async () => {
    const transcript = makeSessionTranscript();
    const mso = await buildMsoWithEcdhDeviceKey(deviceEcdhKeyPair.publicKey);
    const deviceAuth: DeviceAuth = {};

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript, readerEcdhKeyPair.privateKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('No deviceSignature or deviceMac');
  });
});

// ─── API-04: ISO/IEC 18013-5 §9.1.3 structure ───────────────────────────────

describe('API-04: DeviceAuthentication structure', () => {
  test('DeviceAuthenticationBytes = Tag24(bstr(["DeviceAuthentication", ST, DocType, Tag24(DeviceNameSpaces)]))', () => {
    const transcript = makeSessionTranscript();
    const bytes = buildDeviceAuthenticationBytes(transcript, DOCTYPE);
    expect([bytes[0], bytes[1]]).toEqual([0xd8, 0x18]); // Tag 24
    // decode() unwraps Tag 24 recursively, so the inner array is visible in full.
    const decoded = decode<unknown[]>(bytes);
    expect(decoded[0]).toBe('DeviceAuthentication');
    expect(decoded[2]).toBe(DOCTYPE);
    expect(decoded).toHaveLength(4);
    // The fourth element carries its own Tag 24 header on the wire.
    const inner = encode(transcript);
    expect(Buffer.from(bytes).includes(Buffer.from(inner))).toBe(true);
    // Empty DeviceNameSpaces on the wire: Tag 24 (d8 18), bstr(1) (41), map(0) (a0).
    expect([...bytes.subarray(-4)]).toEqual([0xd8, 0x18, 0x41, 0xa0]);
  });

  test('ISO-conformant detached signature verifies; transmitted payload is nil', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    const parsed = decodeCoseSign1(sig);
    expect(parsed.payload).toBeNull();
    expect((await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript, DOCTYPE)).valid).toBe(true);
  });

  test('rejects the pre-fix shape (embedded payload, SessionTranscript as external_aad)', async () => {
    const transcript = makeSessionTranscript();
    const legacy = await signLegacyDeviceAuth(deviceKeyPair.privateKey, transcript);
    const result = await verifyDeviceSignature(legacy, deviceKeyPair.publicKey, transcript, DOCTYPE);
    expect(result.valid).toBe(false);
  });

  test('rejects an embedded payload even when it equals DeviceAuthenticationBytes', async () => {
    const transcript = makeSessionTranscript();
    const embedded = await createSign1({
      payload: buildDeviceAuthenticationBytes(transcript, DOCTYPE),
      privateKey: deviceKeyPair.privateKey,
    });
    expect((await verifyDeviceSignature(embedded, deviceKeyPair.publicKey, transcript, DOCTYPE)).valid).toBe(false);
  });

  test('rejects a signature made for another docType', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript, 'eu.europa.ec.av.1');
    expect((await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript, DOCTYPE)).valid).toBe(false);
  });

  test('rejects a signature when DeviceNameSpaces differ', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);
    const smuggled = new Map<string, unknown>([['org.iso.18013.5.1', new Map([['age_over_18', true]])]]);
    expect(
      (await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript, DOCTYPE, smuggled)).valid
    ).toBe(false);
  });
});
