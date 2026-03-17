/**
 * @module @mitch/mdoc/device-auth
 *
 * ISO 18013-5 Device Authentication verification.
 *
 * Verifies that the holder (device) consents to the disclosure by
 * checking a COSE_Sign1 signature over the SessionTranscript.
 *
 * Phase 1: COSE_Sign1 only — COSE_Mac0 (NFC proximity) is future.
 * Detached payload: fail-closed (not supported in Phase 1).
 */

import type {
  DeviceAuth,
  MobileSecurityObject,
  SessionTranscript,
} from './mdoc-types.js';
import { encode } from './cbor.js';
import { verifySign1 } from './cose.js';
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
 * Full device authentication: extract device key from MSO, then verify signature.
 *
 * 1. Check deviceSignature exists (no MAC support → fail-closed)
 * 2. Import device public key from MSO.deviceKeyInfo.deviceKey via importCoseKey()
 * 3. Verify device signature with SessionTranscript binding
 *
 * Fail-closed: missing deviceKeyInfo, missing deviceSignature → invalid.
 */
export async function verifyDeviceAuth(
  deviceAuth: DeviceAuth,
  mso: MobileSecurityObject,
  sessionTranscript: SessionTranscript,
): Promise<DeviceAuthResult> {
  // Only COSE_Sign1 supported — MAC is future
  if (!deviceAuth.deviceSignature) {
    if (deviceAuth.deviceMac) {
      return { valid: false, reason: 'COSE_Mac0 not supported (only COSE_Sign1)' };
    }
    return { valid: false, reason: 'No deviceSignature in DeviceAuth' };
  }

  // Extract device public key from MSO
  if (!mso.deviceKeyInfo?.deviceKey) {
    return { valid: false, reason: 'MSO missing deviceKeyInfo.deviceKey' };
  }

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
