import {
  canonicalStringify,
  isUsableP256Jwk,
  verifyIdentityAssertion,
  type AssertionFailure,
  type IdentityAssertion,
} from '@askmi/shared-crypto';

/**
 * Signed proof tokens for wallet-initiated requests (erasure, verifier reports,
 * document proofs).
 *
 * Format v2: base64url(header) . base64url(payload) . base64url(signature part)
 * The signature covers "header.payload", so the labels can't be swapped.
 *
 * - key "hardware-passkey", alg "webauthn-es256": the signature part is the full
 *   WebAuthn assertion (JSON), checkable with the passkey public key saved at
 *   registration (verifyIdentityAssertion).
 * - key "software-session", alg "ES256": the signature part is a raw P-256 ECDSA
 *   signature (r||s) from the wallet's software identity key, used only where
 *   WebAuthn is unavailable. Only the session public key can check it.
 *
 * Not RFC 7515 JWS: the hardware variant has no JWS equivalent.
 */

export type ProofTokenKey = 'hardware-passkey' | 'software-session';

export interface ProofTokenHeader {
  typ: 'askmi-poe';
  v: 2;
  alg: 'webauthn-es256' | 'ES256';
  key: ProofTokenKey;
  kid: string;
  enc: 'base64url';
}

export type ProofTokenSigner =
  | {
      key: 'hardware-passkey';
      kid: string;
      sign: (signingInput: string) => Promise<IdentityAssertion>;
    }
  | {
      key: 'software-session';
      kid: string;
      /** raw P-256 ECDSA signature (64 bytes, r||s) over the UTF-8 signing input */
      sign: (signingInput: string) => Promise<Uint8Array>;
    };

export type ProofTokenFailure = AssertionFailure | 'UNSUPPORTED_FORMAT' | 'NO_EXPECTED_RP_ID';

export type ProofTokenVerification =
  | { valid: true; header: ProofTokenHeader; payload: unknown }
  | { valid: false; reason: ProofTokenFailure };

const utf8 = new TextEncoder();

function toBase64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Accepts base64url (and, for reading legacy headers, standard base64). Throws otherwise. */
function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_+/-]*={0,2}$/.test(value) || value.length === 0) {
    throw new Error('not base64');
  }
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  return Uint8Array.from(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)), (c) =>
    c.charCodeAt(0)
  );
}

const jsonPart = (part: string): unknown => JSON.parse(new TextDecoder().decode(fromBase64(part)));

export async function createProofToken(
  payload: unknown,
  signer: ProofTokenSigner
): Promise<string> {
  const header: ProofTokenHeader = {
    typ: 'askmi-poe',
    v: 2,
    alg: signer.key === 'hardware-passkey' ? 'webauthn-es256' : 'ES256',
    key: signer.key,
    kid: signer.kid,
    enc: 'base64url',
  };
  const signingInput = `${toBase64url(utf8.encode(canonicalStringify(header)))}.${toBase64url(
    utf8.encode(canonicalStringify(payload))
  )}`;

  const signaturePart =
    signer.key === 'hardware-passkey'
      ? toBase64url(utf8.encode(canonicalStringify(await signer.sign(signingInput))))
      : toBase64url(await signer.sign(signingInput));

  return `${signingInput}.${signaturePart}`;
}

/** The token header if it is a v2 proof token, otherwise null. */
export function decodeProofTokenHeader(token: string): ProofTokenHeader | null {
  try {
    const header = jsonPart(token.split('.')[0]) as Partial<ProofTokenHeader>;
    return header?.typ === 'askmi-poe' && header.v === 2 ? (header as ProofTokenHeader) : null;
  } catch {
    return null;
  }
}

/**
 * Verify a v2 proof token. Never throws. A hardware token needs the stored passkey
 * public key and the expected rpId; a software token needs the session public key.
 */
export async function verifyProofToken(
  token: string,
  opts: {
    publicKeyJwk?: JsonWebKey | null;
    expectedRpId?: string;
    expectedOrigin?: string;
    softwarePublicKey?: CryptoKey | null;
  }
): Promise<ProofTokenVerification> {
  const fail = (reason: ProofTokenFailure): ProofTokenVerification => ({ valid: false, reason });

  const parts = token.split('.');
  if (parts.length !== 3) return fail('MALFORMED');
  const [headerPart, payloadPart, signaturePart] = parts;

  let header: Partial<ProofTokenHeader>;
  let payload: unknown;
  try {
    header = jsonPart(headerPart) as Partial<ProofTokenHeader>;
    if (typeof header !== 'object' || header === null) return fail('MALFORMED');
  } catch {
    return fail('MALFORMED');
  }
  if (header.typ !== 'askmi-poe' || header.v !== 2) return fail('UNSUPPORTED_FORMAT');
  try {
    payload = jsonPart(payloadPart);
  } catch {
    return fail('MALFORMED');
  }

  const signingInput = `${headerPart}.${payloadPart}`;
  const ok = (): ProofTokenVerification => ({
    valid: true,
    header: header as ProofTokenHeader,
    payload,
  });

  if (header.key === 'hardware-passkey' && header.alg === 'webauthn-es256') {
    if (!isUsableP256Jwk(opts.publicKeyJwk)) return fail('NO_PUBLIC_KEY');
    if (!opts.expectedRpId) return fail('NO_EXPECTED_RP_ID');
    let assertion: IdentityAssertion;
    try {
      assertion = jsonPart(signaturePart) as IdentityAssertion;
    } catch {
      return fail('MALFORMED');
    }
    const result = await verifyIdentityAssertion({
      data: signingInput,
      assertion,
      publicKeyJwk: opts.publicKeyJwk,
      expectedRpId: opts.expectedRpId,
      expectedOrigin: opts.expectedOrigin,
    });
    return result.valid ? ok() : fail(result.reason);
  }

  if (header.key === 'software-session' && header.alg === 'ES256') {
    if (!opts.softwarePublicKey) return fail('NO_PUBLIC_KEY');
    let signature: Uint8Array<ArrayBuffer>;
    try {
      signature = fromBase64(signaturePart);
    } catch {
      return fail('MALFORMED');
    }
    if (signature.length !== 64) return fail('MALFORMED');
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      opts.softwarePublicKey,
      signature,
      utf8.encode(signingInput)
    );
    return valid ? ok() : fail('BAD_SIGNATURE');
  }

  return fail('UNSUPPORTED_FORMAT');
}
