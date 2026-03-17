import { describe, test, expect, beforeAll } from 'vitest';
import { verifyDeviceSignature, verifyDeviceAuth } from '../src/device-auth';
import { exportCoseKey } from '../src/cose-key';
import { createSign1 } from '../src/cose';
import { encode } from '../src/cbor';
import type {
  DeviceAuth,
  MobileSecurityObject,
  SessionTranscript,
} from '../src/mdoc-types';

// ─── Test Key Setup ─────────────────────────────────────────────────────────

let deviceKeyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair;

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
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeSessionTranscript(): SessionTranscript {
  return [
    new Uint8Array([0x01, 0x02, 0x03]), // deviceEngagementBytes
    new Uint8Array([0x04, 0x05, 0x06]), // eReaderKeyBytes
    'handover-data',                     // handover
  ];
}

async function signDeviceAuth(
  privateKey: CryptoKey,
  sessionTranscript: SessionTranscript,
): Promise<Uint8Array> {
  const externalAad = encode(sessionTranscript);
  const payload = encode({ deviceNameSpaces: {} });
  return createSign1({
    payload,
    privateKey,
    externalAad,
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

// ─── verifyDeviceSignature ──────────────────────────────────────────────────

describe('verifyDeviceSignature', () => {
  test('valid: correct key + SessionTranscript', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const result = await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  test('invalid: wrong device key', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const result = await verifyDeviceSignature(sig, otherKeyPair.publicKey, transcript);
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

    const result = await verifyDeviceSignature(sig, deviceKeyPair.publicKey, tamperedTranscript);
    expect(result.valid).toBe(false);
  });

  test('invalid: corrupted signature bytes', async () => {
    const transcript = makeSessionTranscript();
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    // Corrupt the bytes
    const corrupted = new Uint8Array(sig);
    corrupted[corrupted.length - 1] ^= 0xff;

    const result = await verifyDeviceSignature(corrupted, deviceKeyPair.publicKey, transcript);
    expect(result.valid).toBe(false);
  });

  test('null SessionTranscript fields accepted', async () => {
    const transcript: SessionTranscript = [null, null, 'handover'];
    const sig = await signDeviceAuth(deviceKeyPair.privateKey, transcript);

    const result = await verifyDeviceSignature(sig, deviceKeyPair.publicKey, transcript);
    expect(result.valid).toBe(true);
  });

  test('invalid: garbage bytes', async () => {
    const transcript = makeSessionTranscript();
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03]);

    const result = await verifyDeviceSignature(garbage, deviceKeyPair.publicKey, transcript);
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

  test('invalid: deviceMac without deviceSignature', async () => {
    const transcript = makeSessionTranscript();
    const mso = await buildMsoWithDeviceKey(deviceKeyPair.publicKey);
    const deviceAuth: DeviceAuth = { deviceMac: new Uint8Array([0x01]) };

    const result = await verifyDeviceAuth(deviceAuth, mso, transcript);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('COSE_Mac0 not supported');
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
