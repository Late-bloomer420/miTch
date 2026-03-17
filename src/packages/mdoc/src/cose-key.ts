/**
 * @module @mitch/mdoc/cose-key
 *
 * COSE_Key import for ISO 18013-5 device key verification.
 * Supports EC2 (P-256) keys per RFC 9052 §7.1.
 *
 * Phase 1: import only (COSE_Key → CryptoKey for verification).
 * Export helper provided for test roundtrips.
 */

import { mapGet } from './util.js';

/** COSE_Key integer labels per RFC 9052 §7.1 */
export const COSE_KEY = {
  KTY: 1,
  ALG: 3,
  CRV: -1,
  X: -2,
  Y: -3,
  KTY_EC2: 2,
  CRV_P256: 1,
} as const;

function base64urlEncode(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Import a COSE_Key (EC2 P-256) into a WebCrypto CryptoKey for signature verification.
 *
 * Handles both Map (native) and plain object (CBOR-decoded) representations.
 * Fail-closed: unsupported key type, missing coordinates → throws.
 */
export async function importCoseKey(
  coseKey: Map<number, unknown> | Record<number, unknown>
): Promise<CryptoKey> {
  const kty = mapGet(coseKey, COSE_KEY.KTY);
  if (kty !== COSE_KEY.KTY_EC2) {
    throw new Error(`Unsupported COSE_Key type: ${kty} (expected EC2 = ${COSE_KEY.KTY_EC2})`);
  }

  const crv = mapGet(coseKey, COSE_KEY.CRV);
  if (crv !== COSE_KEY.CRV_P256) {
    throw new Error(`Unsupported COSE_Key curve: ${crv} (expected P-256 = ${COSE_KEY.CRV_P256})`);
  }

  const x = mapGet(coseKey, COSE_KEY.X) as Uint8Array | undefined;
  const y = mapGet(coseKey, COSE_KEY.Y) as Uint8Array | undefined;

  if (!x || !y) {
    throw new Error('COSE_Key missing x or y coordinate');
  }

  if (x.length !== 32 || y.length !== 32) {
    throw new Error(`Invalid P-256 coordinate length: x=${x.length}, y=${y.length} (expected 32)`);
  }

  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlEncode(x),
    y: base64urlEncode(y),
  };

  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

/**
 * Export a WebCrypto P-256 public key to a COSE_Key map.
 * Used for test roundtrips — requires extractable key.
 */
export async function exportCoseKey(
  publicKey: CryptoKey
): Promise<Map<number, unknown>> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);

  if (!jwk.x || !jwk.y) {
    throw new Error('Cannot export: key has no x/y coordinates');
  }

  const coseKey = new Map<number, unknown>();
  coseKey.set(COSE_KEY.KTY, COSE_KEY.KTY_EC2);
  coseKey.set(COSE_KEY.CRV, COSE_KEY.CRV_P256);
  coseKey.set(COSE_KEY.X, base64urlDecode(jwk.x));
  coseKey.set(COSE_KEY.Y, base64urlDecode(jwk.y));
  return coseKey;
}
