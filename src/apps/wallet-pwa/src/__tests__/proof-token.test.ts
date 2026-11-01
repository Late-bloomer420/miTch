import { describe, expect, it } from 'vitest';
import { identityChallenge, type IdentityAssertion } from '@askmi/shared-crypto';
import {
  createProofToken,
  decodeProofTokenHeader,
  verifyProofToken,
  type ProofTokenSigner,
} from '../utils/proof-token';

const enc = new TextEncoder();
const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

async function p256() {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  return { keys, jwk: await crypto.subtle.exportKey('jwk', keys.publicKey) };
}

function p1363ToDer(sig: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = Uint8Array.of(0, ...v);
    return Uint8Array.of(0x02, v.length, ...v);
  };
  const r = int(sig.slice(0, 32));
  const s = int(sig.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

/** Software signer: raw P-256 ECDSA (P1363), like the wallet's session identity key. */
async function softwareSigner() {
  const { keys } = await p256();
  const signer: ProofTokenSigner = {
    key: 'software-session',
    kid: 'did:askmi:user-wallet-001#software-identity-key',
    sign: async (input) =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          keys.privateKey,
          enc.encode(input)
        )
      ),
  };
  return { signer, publicKey: keys.publicKey };
}

/** Hardware signer: a simulated passkey answering like navigator.credentials.get. */
async function passkeySigner(rpId = 'wallet.example') {
  const { keys, jwk } = await p256();
  const signer: ProofTokenSigner = {
    key: 'hardware-passkey',
    kid: 'did:askmi:user-wallet-001#passkey-identity-key',
    sign: async (input): Promise<IdentityAssertion> => {
      const clientDataJSON = enc.encode(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: b64url(new Uint8Array(await identityChallenge(input))),
          origin: 'https://wallet.example',
        })
      );
      const authenticatorData = new Uint8Array(37);
      authenticatorData.set(await sha256(enc.encode(rpId)), 0);
      authenticatorData[32] = 0x05;
      const signed = new Uint8Array([...authenticatorData, ...(await sha256(clientDataJSON))]);
      const sig = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, signed)
      );
      return {
        version: 1,
        credentialId: 'cred-1',
        rpId,
        authenticatorData: b64url(authenticatorData),
        clientDataJSON: b64url(clientDataJSON),
        signature: b64url(p1363ToDer(sig)),
      };
    },
  };
  return { signer, jwk };
}

const PAYLOAD = { type: 'ProofOfExistence', hash: 'abc123', hashAlg: 'SHA-256' };

/** Replace one dot-separated part of a token. */
const withPart = (token: string, index: number, value: string) =>
  token
    .split('.')
    .map((p, i) => (i === index ? value : p))
    .join('.');

describe('proof tokens: software session key', () => {
  it('labels the token and verifies with the session public key', async () => {
    const { signer, publicKey } = await softwareSigner();
    const token = await createProofToken(PAYLOAD, signer);

    expect(token.split('.')).toHaveLength(3);
    expect(decodeProofTokenHeader(token)).toEqual({
      typ: 'askmi-poe',
      v: 2,
      alg: 'ES256',
      key: 'software-session',
      kid: 'did:askmi:user-wallet-001#software-identity-key',
      enc: 'base64url',
    });
    const result = await verifyProofToken(token, { softwarePublicKey: publicKey });
    expect(result).toEqual({
      valid: true,
      header: decodeProofTokenHeader(token),
      payload: PAYLOAD,
    });
  });

  it('rejects a changed payload', async () => {
    const { signer, publicKey } = await softwareSigner();
    const token = await createProofToken(PAYLOAD, signer);
    const forged = withPart(
      token,
      1,
      b64url(enc.encode(JSON.stringify({ ...PAYLOAD, hash: 'x' })))
    );
    expect(await verifyProofToken(forged, { softwarePublicKey: publicKey })).toEqual({
      valid: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  it('covers the header too: a changed kid breaks the signature', async () => {
    const { signer, publicKey } = await softwareSigner();
    const token = await createProofToken(PAYLOAD, signer);
    const header = { ...decodeProofTokenHeader(token)!, kid: 'did:askmi:someone-else#key' };
    const forged = withPart(token, 0, b64url(enc.encode(JSON.stringify(header))));
    expect(await verifyProofToken(forged, { softwarePublicKey: publicKey })).toEqual({
      valid: false,
      reason: 'BAD_SIGNATURE',
    });
  });

  it('reports NO_PUBLIC_KEY when no session key is given', async () => {
    const { signer } = await softwareSigner();
    const token = await createProofToken(PAYLOAD, signer);
    expect(await verifyProofToken(token, {})).toEqual({ valid: false, reason: 'NO_PUBLIC_KEY' });
  });
});

describe('proof tokens: hardware passkey', () => {
  it('labels the token and verifies against the stored passkey public key', async () => {
    const { signer, jwk } = await passkeySigner();
    const token = await createProofToken(PAYLOAD, signer);

    expect(decodeProofTokenHeader(token)).toMatchObject({
      alg: 'webauthn-es256',
      key: 'hardware-passkey',
      enc: 'base64url',
    });
    const result = await verifyProofToken(token, {
      publicKeyJwk: jwk,
      expectedRpId: 'wallet.example',
      expectedOrigin: 'https://wallet.example',
    });
    expect(result).toMatchObject({ valid: true, payload: PAYLOAD });
  });

  it('rejects a changed payload (challenge no longer matches)', async () => {
    const { signer, jwk } = await passkeySigner();
    const token = await createProofToken(PAYLOAD, signer);
    const forged = withPart(
      token,
      1,
      b64url(enc.encode(JSON.stringify({ ...PAYLOAD, hash: 'x' })))
    );
    expect(
      await verifyProofToken(forged, { publicKeyJwk: jwk, expectedRpId: 'wallet.example' })
    ).toEqual({ valid: false, reason: 'CHALLENGE_MISMATCH' });
  });

  it('rejects a token signed by a different passkey', async () => {
    const { signer } = await passkeySigner();
    const other = await passkeySigner();
    const token = await createProofToken(PAYLOAD, signer);
    expect(
      await verifyProofToken(token, { publicKeyJwk: other.jwk, expectedRpId: 'wallet.example' })
    ).toEqual({ valid: false, reason: 'BAD_SIGNATURE' });
  });

  it('cannot be checked without the stored public key or the expected rpId', async () => {
    const { signer, jwk } = await passkeySigner();
    const token = await createProofToken(PAYLOAD, signer);
    expect(await verifyProofToken(token, { expectedRpId: 'wallet.example' })).toEqual({
      valid: false,
      reason: 'NO_PUBLIC_KEY',
    });
    expect(await verifyProofToken(token, { publicKeyJwk: jwk })).toEqual({
      valid: false,
      reason: 'NO_EXPECTED_RP_ID',
    });
  });
});

describe('proof tokens: malformed and legacy input', () => {
  it('rejects the old unlabelled v1 format (ES256-PoC, hex signature)', async () => {
    const legacy = `${btoa('{"alg":"ES256-PoC","kid":"x"}')}.${btoa('{}')}.${'ab'.repeat(64)}`;
    expect(await verifyProofToken(legacy, {})).toEqual({
      valid: false,
      reason: 'UNSUPPORTED_FORMAT',
    });
  });

  it('reports MALFORMED instead of throwing on garbage', async () => {
    for (const bad of ['', 'a.b', 'a.b.c.d', '!!.??.**']) {
      expect(await verifyProofToken(bad, {})).toEqual({ valid: false, reason: 'MALFORMED' });
    }
  });
});
