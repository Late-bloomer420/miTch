/**
 * Verifiable WebAuthn identity assertions.
 *
 * A passkey does not sign the caller's data directly. It signs
 * `authenticatorData || SHA-256(clientDataJSON)`, where clientDataJSON carries the
 * challenge. To make a hardware identity signature checkable, the challenge is
 * SHA-256(data), and the assertion keeps authenticatorData, clientDataJSON and
 * the signature together. `verifyIdentityAssertion` checks all of it against the
 * public key saved at registration.
 *
 * Runs in browsers and Node (WebCrypto only, no Buffer).
 */

export interface IdentityAssertion {
  version: 1;
  /** base64url credential ID of the passkey that signed */
  credentialId: string;
  /** relying-party ID the passkey is bound to */
  rpId: string;
  /** base64url authenticatorData as returned by the authenticator */
  authenticatorData: string;
  /** base64url clientDataJSON as returned by the browser */
  clientDataJSON: string;
  /** base64url DER-encoded ECDSA P-256 signature (as returned by WebAuthn) */
  signature: string;
}

export type AssertionFailure =
  | 'NO_PUBLIC_KEY'
  | 'MALFORMED'
  | 'WRONG_TYPE'
  | 'CHALLENGE_MISMATCH'
  | 'ORIGIN_MISMATCH'
  | 'RP_ID_MISMATCH'
  | 'USER_NOT_PRESENT'
  | 'USER_NOT_VERIFIED'
  | 'BAD_SIGNATURE';

export type AssertionVerification = { valid: true } | { valid: false; reason: AssertionFailure };

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;

const utf8 = new TextEncoder();

function toBytes(view: ArrayBuffer | Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(view instanceof Uint8Array ? view.slice().buffer : view.slice(0));
}

export function bytesToBase64url(bytes: ArrayBuffer | Uint8Array): string {
  const b = toBytes(bytes);
  let s = '';
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Throws on input that is not base64url. */
export function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('not base64url');
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** The WebAuthn challenge used for identity signatures: SHA-256 of the UTF-8 data. */
export async function identityChallenge(data: string): Promise<ArrayBuffer> {
  return (await sha256(utf8.encode(data))).buffer;
}

/**
 * Convert a DER ECDSA signature (WebAuthn's format) to the 64-byte r||s form
 * WebCrypto verifies. Returns null if the input is not a P-256 DER signature.
 */
export function derToP1363(der: Uint8Array): Uint8Array | null {
  let i = 0;
  const readInt = (): Uint8Array | null => {
    if (der[i++] !== 0x02) return null;
    const len = der[i++];
    if (len === undefined || len < 1 || i + len > der.length) return null;
    let value = der.slice(i, i + len);
    i += len;
    while (value.length > 1 && value[0] === 0) value = value.slice(1);
    if (value.length > 32) return null;
    const out = new Uint8Array(32);
    out.set(value, 32 - value.length);
    return out;
  };
  if (der.length < 8 || der[i++] !== 0x30) return null;
  const total = der[i++];
  if (total !== der.length - 2) return null;
  const r = readInt();
  const s = r && readInt();
  if (!r || !s || i !== der.length) return null;
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

/** True for a P-256 public JWK with real coordinates (the legacy placeholder has empty x/y). */
export function isUsableP256Jwk(jwk: JsonWebKey | null | undefined): jwk is JsonWebKey {
  return Boolean(jwk && jwk.kty === 'EC' && jwk.crv === 'P-256' && jwk.x && jwk.y);
}

/** Registration public key (SPKI, from getPublicKey()) → P-256 JWK, or null if not P-256. */
export async function spkiToP256Jwk(spki: ArrayBuffer): Promise<JsonWebKey | null> {
  try {
    const key = await crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);
    return isUsableP256Jwk(jwk) ? { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } : null;
  } catch {
    return null;
  }
}

/**
 * Verify an identity assertion over `data`. Never throws: any problem is reported
 * as `{ valid: false, reason }`, so callers can treat everything but `valid: true`
 * as unverified.
 */
export async function verifyIdentityAssertion(input: {
  data: string;
  assertion: IdentityAssertion;
  publicKeyJwk: JsonWebKey | null | undefined;
  expectedRpId: string;
  /** checked only when given (e.g. https://wallet.example) */
  expectedOrigin?: string;
}): Promise<AssertionVerification> {
  const fail = (reason: AssertionFailure): AssertionVerification => ({ valid: false, reason });
  const { data, assertion, publicKeyJwk, expectedRpId, expectedOrigin } = input;

  if (!isUsableP256Jwk(publicKeyJwk)) return fail('NO_PUBLIC_KEY');

  let authenticatorData: Uint8Array<ArrayBuffer>;
  let clientDataBytes: Uint8Array<ArrayBuffer>;
  let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
  let signatureDer: Uint8Array;
  try {
    authenticatorData = base64urlToBytes(assertion.authenticatorData);
    clientDataBytes = base64urlToBytes(assertion.clientDataJSON);
    clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
    signatureDer = base64urlToBytes(assertion.signature);
  } catch {
    return fail('MALFORMED');
  }
  if (authenticatorData.length < 37 || typeof clientData !== 'object' || clientData === null) {
    return fail('MALFORMED');
  }

  if (clientData.type !== 'webauthn.get') return fail('WRONG_TYPE');

  const expectedChallenge = bytesToBase64url(await identityChallenge(data));
  if (clientData.challenge !== expectedChallenge) return fail('CHALLENGE_MISMATCH');

  if (expectedOrigin !== undefined && clientData.origin !== expectedOrigin) {
    return fail('ORIGIN_MISMATCH');
  }

  const rpIdHash = await sha256(utf8.encode(expectedRpId));
  if (!equalBytes(authenticatorData.slice(0, 32), rpIdHash)) return fail('RP_ID_MISMATCH');

  const flags = authenticatorData[32];
  if (!(flags & FLAG_USER_PRESENT)) return fail('USER_NOT_PRESENT');
  if (!(flags & FLAG_USER_VERIFIED)) return fail('USER_NOT_VERIFIED');

  const signature = derToP1363(signatureDer);
  if (!signature) return fail('MALFORMED');

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: publicKeyJwk.x, y: publicKeyJwk.y },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  } catch {
    return fail('NO_PUBLIC_KEY');
  }

  const signed = new Uint8Array(authenticatorData.length + 32);
  signed.set(authenticatorData, 0);
  signed.set(await sha256(clientDataBytes), authenticatorData.length);

  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    toBytes(signature),
    signed
  );
  return ok ? { valid: true } : fail('BAD_SIGNATURE');
}
