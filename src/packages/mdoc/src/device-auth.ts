/**
 * @module @mitch/mdoc/device-auth
 *
 * ISO 18013-5 Device Authentication verification.
 *
 * Verifies that the holder (device) consents to the disclosure by
 * checking either:
 * - COSE_Sign1 signature over the SessionTranscript (general case)
 * - COSE_Mac0 MAC over the SessionTranscript (NFC proximity, ECDH key agreement)
 *
 * Detached payload: fail-closed (not supported).
 */

import type {
  DeviceAuth,
  MobileSecurityObject,
  SessionTranscript,
} from './mdoc-types.js';
import { encode } from './cbor.js';
import { verifySign1, verifyMac0, deriveSessionMacKey } from './cose.js';
import { importCoseKey } from './cose-key.js';

/** Result of device authentication verification. */
export interface DeviceAuthResult {
  valid: boolean;
  reason?: string;
}

/**
 * Verify a device COSE_Sign1 signature with SessionTranscript binding.
 *
 * Per ISO 18013-5 §9.1.3.6:
 * - SessionTranscript is CBOR-encoded and used as externalAad
 * - The device signs over the SessionTranscript context, binding
 *   the signature to the specific session
 *
 * Fail-closed: detached payload (null) → invalid.
 */
export async function verifyDeviceSignature(
  deviceSignature: Uint8Array,
  devicePublicKey: CryptoKey,
  sessionTranscript: SessionTranscript,
): Promise<DeviceAuthResult> {
  // Encode SessionTranscript as CBOR → externalAad
  const externalAad = encode(sessionTranscript);

  let result;
  try {
    result = await verifySign1(deviceSignature, devicePublicKey, externalAad);
  } catch {
    return { valid: false, reason: 'COSE_Sign1 decoding failed' };
  }

  if (!result.valid) {
    return { valid: false, reason: 'Device signature invalid' };
  }

  // Detached payload: fail-closed (only reachable if signature was valid but payload missing)
  if (result.payload === null) {
    return { valid: false, reason: 'Detached payload not supported (payload is null)' };
  }

  return { valid: true };
}

/**
 * Verify a device COSE_Mac0 tag with SessionTranscript binding.
 *
 * Per ISO 18013-5 §9.1.1.5:
 * - Device and reader perform ECDH key agreement
 * - Shared secret → HKDF → HMAC key (EMacKey)
 * - Device MACs the session context with this key
 *
 * @param deviceMac - COSE_Mac0 bytes from DeviceAuth
 * @param macKey - Pre-derived HMAC key (from ECDH + HKDF)
 * @param sessionTranscript - SessionTranscript for external AAD binding
 */
export async function verifyDeviceMac(
  deviceMac: Uint8Array,
  macKey: CryptoKey,
  sessionTranscript: SessionTranscript,
): Promise<DeviceAuthResult> {
  const externalAad = encode(sessionTranscript);

  let result;
  try {
    result = await verifyMac0(deviceMac, macKey, externalAad);
  } catch {
    return { valid: false, reason: 'COSE_Mac0 decoding failed' };
  }

  if (!result.valid) {
    return { valid: false, reason: 'Device MAC tag invalid' };
  }

  if (result.payload === null) {
    return { valid: false, reason: 'Detached payload not supported (payload is null)' };
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

    return verifyDeviceMac(deviceAuth.deviceMac, macKey, sessionTranscript);
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
