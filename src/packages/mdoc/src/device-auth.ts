/**
 * @module @askmi/mdoc/device-auth
 *
 * ISO 18013-5 Device Authentication verification.
 *
 * Verifies that the holder (device) consents to the disclosure by
 * checking either:
 * - COSE_Sign1 signature (general case)
 * - COSE_Mac0 MAC (ECDH key agreement)
 * over DeviceAuthenticationBytes with detached payload (ISO/IEC 18013-5 §9.1.3).
 */

import type {
  DeviceAuth,
  MobileSecurityObject,
  SessionTranscript,
} from './mdoc-types.js';
import { encode, wrapEmbeddedCborBytes } from './cbor.js';
import { verifySign1, verifyMac0, deriveSessionMacKey } from './cose.js';
import { importCoseKey } from './cose-key.js';

/** Result of device authentication verification. */
export interface DeviceAuthResult {
  valid: boolean;
  reason?: string;
}

/**
 * Build `DeviceAuthenticationBytes` per ISO/IEC 18013-5 §9.1.3.4:
 *
 *   DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
 *   DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)
 *   DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
 *
 * Known limit: DeviceNameSpaces is re-encoded from the parsed map. A third-party
 * wallet whose original encoding differs (non-canonical order/length) would not
 * verify until the parser keeps the raw DeviceNameSpacesBytes.
 */
export function buildDeviceAuthenticationBytes(
  sessionTranscript: SessionTranscript,
  docType: string,
  deviceNameSpaces: Map<string, unknown> = new Map(),
): Uint8Array {
  const deviceNameSpacesBytes = wrapEmbeddedCborBytes(encode(deviceNameSpaces));
  // CBOR array(4) header + elements; the fourth element is already a Tag 24 item.
  const parts = [
    new Uint8Array([0x84]),
    encode('DeviceAuthentication'),
    encode(sessionTranscript),
    encode(docType),
    deviceNameSpacesBytes,
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const deviceAuthentication = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    deviceAuthentication.set(p, offset);
    offset += p.length;
  }
  return wrapEmbeddedCborBytes(deviceAuthentication);
}

/**
 * Verify a device COSE_Sign1 signature (ISO/IEC 18013-5 §9.1.3.6, API-04).
 *
 * The deviceSignature is a COSE_Sign1 with **detached** payload (nil) and empty
 * external_aad; the signed content is DeviceAuthenticationBytes over the
 * SessionTranscript, DocType and DeviceNameSpaces. An embedded payload, an
 * external_aad binding, or a signature over another session/docType is rejected.
 */
export async function verifyDeviceSignature(
  deviceSignature: Uint8Array,
  devicePublicKey: CryptoKey,
  sessionTranscript: SessionTranscript,
  docType: string,
  deviceNameSpaces: Map<string, unknown> = new Map(),
): Promise<DeviceAuthResult> {
  const detached = buildDeviceAuthenticationBytes(sessionTranscript, docType, deviceNameSpaces);

  let result;
  try {
    result = await verifySign1(deviceSignature, devicePublicKey, new Uint8Array(0), detached);
  } catch {
    return { valid: false, reason: 'COSE_Sign1 decoding failed' };
  }

  if (!result.valid) {
    return { valid: false, reason: 'Device signature invalid' };
  }
  return { valid: true };
}

/**
 * Verify a device COSE_Mac0 tag (ISO/IEC 18013-5 §9.1.3.5, API-04).
 *
 * Same content rule as the signature path: detached payload, empty external_aad,
 * MAC over DeviceAuthenticationBytes.
 *
 * @param deviceMac - COSE_Mac0 bytes from DeviceAuth
 * @param macKey - Pre-derived HMAC key (from ECDH + HKDF)
 * @param sessionTranscript - SessionTranscript bound inside DeviceAuthenticationBytes
 */
export async function verifyDeviceMac(
  deviceMac: Uint8Array,
  macKey: CryptoKey,
  sessionTranscript: SessionTranscript,
  docType: string,
  deviceNameSpaces: Map<string, unknown> = new Map(),
): Promise<DeviceAuthResult> {
  const detached = buildDeviceAuthenticationBytes(sessionTranscript, docType, deviceNameSpaces);

  let result;
  try {
    result = await verifyMac0(deviceMac, macKey, new Uint8Array(0), detached);
  } catch {
    return { valid: false, reason: 'COSE_Mac0 decoding failed' };
  }

  if (!result.valid) {
    return { valid: false, reason: 'Device MAC tag invalid' };
  }
  return { valid: true };
}

/**
 * Full device authentication: extract device key from MSO, then verify.
 *
 * Supports both authentication methods:
 * - COSE_Sign1 (deviceSignature): ECDSA verification with device public key
 * - COSE_Mac0 (deviceMac): requires eReaderKey for ECDH key derivation
 *
 * Fail-closed: missing both deviceSignature and deviceMac → invalid.
 *
 * @param eReaderPrivateKey - Reader's ECDH private key (required for Mac0 path)
 */
export async function verifyDeviceAuth(
  deviceAuth: DeviceAuth,
  mso: MobileSecurityObject,
  sessionTranscript: SessionTranscript,
  eReaderPrivateKey?: CryptoKey,
  deviceNameSpaces: Map<string, unknown> = new Map(),
): Promise<DeviceAuthResult> {
  // Extract device public key from MSO (needed for both paths)
  if (!mso.deviceKeyInfo?.deviceKey) {
    return { valid: false, reason: 'MSO missing deviceKeyInfo.deviceKey' };
  }

  // COSE_Sign1 path (preferred when available)
  if (deviceAuth.deviceSignature) {
    let devicePublicKey: CryptoKey;
    try {
      devicePublicKey = await importCoseKey(mso.deviceKeyInfo.deviceKey);
    } catch (err) {
      return {
        valid: false,
        reason: `Device key import failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    return verifyDeviceSignature(
      deviceAuth.deviceSignature,
      devicePublicKey,
      sessionTranscript,
      mso.docType,
      deviceNameSpaces,
    );
  }

  // COSE_Mac0 path (NFC proximity)
  if (deviceAuth.deviceMac) {
    if (!eReaderPrivateKey) {
      return { valid: false, reason: 'COSE_Mac0 requires eReaderPrivateKey for ECDH key agreement' };
    }

    // Import device public key as ECDH key for key agreement
    let deviceEcdhKey: CryptoKey;
    try {
      deviceEcdhKey = await importCoseKeyForEcdh(mso.deviceKeyInfo.deviceKey);
    } catch (err) {
      return {
        valid: false,
        reason: `Device ECDH key import failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // Derive MAC key via ECDH + HKDF
    let macKey: CryptoKey;
    try {
      macKey = await deriveSessionMacKey(eReaderPrivateKey, deviceEcdhKey);
    } catch (err) {
      return {
        valid: false,
        reason: `MAC key derivation failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    return verifyDeviceMac(deviceAuth.deviceMac, macKey, sessionTranscript, mso.docType, deviceNameSpaces);
  }

  return { valid: false, reason: 'No deviceSignature or deviceMac in DeviceAuth' };
}

/**
 * Import a COSE_Key as an ECDH public key (for key agreement).
 * Similar to importCoseKey but with ECDH key usage instead of ECDSA verify.
 */
async function importCoseKeyForEcdh(
  coseKey: Map<number, unknown>,
): Promise<CryptoKey> {
  // COSE_Key: kty=2 (EC2), crv=1 (P-256), x=(-2), y=(-3)
  const x = coseKey.get(-2) as Uint8Array;
  const y = coseKey.get(-3) as Uint8Array;
  if (!x || !y) {
    throw new Error('COSE_Key missing x or y coordinate');
  }

  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: uint8ArrayToBase64url(x),
    y: uint8ArrayToBase64url(y),
  };

  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}

function uint8ArrayToBase64url(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
