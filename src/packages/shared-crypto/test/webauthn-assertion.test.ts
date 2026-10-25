import { describe, it, expect } from 'vitest';
import {
  derToP1363,
  identityChallenge,
  isUsableP256Jwk,
  spkiToP256Jwk,
  verifyIdentityAssertion,
  type IdentityAssertion,
} from '../src/webauthn-assertion';

import { b64url, makeKeyPair, signAssertion } from './helpers/fake-authenticator';

interface FakeAuthOptions {
  rpId?: string;
  flags?: number;
  type?: string;
  origin?: string;
  challengeFor?: string;
}

async function makeAuthenticator() {
  const { keys, jwk, spki } = await makeKeyPair();

  async function assert(data: string, opts: FakeAuthOptions = {}): Promise<IdentityAssertion> {
    const parts = await signAssertion(keys.privateKey, {
      rpId: opts.rpId ?? 'wallet.example',
      challenge: await identityChallenge(opts.challengeFor ?? data),
      origin: opts.origin,
      flags: opts.flags,
      type: opts.type,
    });
    return {
      version: 1,
      credentialId: 'cred-1',
      rpId: 'wallet.example',
      authenticatorData: b64url(parts.authenticatorData),
      clientDataJSON: b64url(parts.clientDataJSON),
      signature: b64url(parts.signature),
    };
  }

  return { jwk, spki, assert };
}

const DATA = '{"hash":"abc","purpose":"erasure"}';

describe('verifyIdentityAssertion', () => {
  it('accepts a genuine assertion over the data', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
      expectedOrigin: 'https://wallet.example',
    });
    expect(result).toEqual({ valid: true });
  });

  it('rejects when the signed challenge is for different data', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA, { challengeFor: 'other data' }),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'CHALLENGE_MISMATCH' });
  });

  it('rejects an assertion made for another site (rpId hash)', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA, { rpId: 'evil.example' }),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'RP_ID_MISMATCH' });
  });

  it('rejects when the user was not verified (UV flag missing)', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA, { flags: 0x01 }),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'USER_NOT_VERIFIED' });
  });

  it('rejects when the user was not present (UP flag missing)', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA, { flags: 0x04 }),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'USER_NOT_PRESENT' });
  });

  it('rejects a registration-type client data', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA, { type: 'webauthn.create' }),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'WRONG_TYPE' });
  });

  it('rejects an origin mismatch when an origin is expected', async () => {
    const auth = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA, { origin: 'https://evil.example' }),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
      expectedOrigin: 'https://wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'ORIGIN_MISMATCH' });
  });

  it('rejects a tampered authenticatorData (signature no longer matches)', async () => {
    const auth = await makeAuthenticator();
    const assertion = await auth.assert(DATA);
    const raw = Uint8Array.from(
      atob(assertion.authenticatorData.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0)
    );
    raw[36] ^= 0x01; // change the sign counter only; rpId hash and flags stay valid
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: { ...assertion, authenticatorData: b64url(raw) },
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'BAD_SIGNATURE' });
  });

  it('rejects a signature from a different key', async () => {
    const auth = await makeAuthenticator();
    const other = await makeAuthenticator();
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await other.assert(DATA),
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'BAD_SIGNATURE' });
  });

  it('reports NO_PUBLIC_KEY for the legacy placeholder key (empty x/y)', async () => {
    const auth = await makeAuthenticator();
    const placeholder = { kty: 'EC', crv: 'P-256', x: '', y: '', alg: 'ES256', ext: true };
    const result = await verifyIdentityAssertion({
      data: DATA,
      assertion: await auth.assert(DATA),
      publicKeyJwk: placeholder,
      expectedRpId: 'wallet.example',
    });
    expect(result).toEqual({ valid: false, reason: 'NO_PUBLIC_KEY' });
  });

  it('reports MALFORMED instead of throwing on garbage input', async () => {
    const auth = await makeAuthenticator();
    const good = await auth.assert(DATA);
    for (const bad of [
      { ...good, authenticatorData: 'AAAA' },
      { ...good, clientDataJSON: '!!not-base64!!' },
      { ...good, signature: 'AQID' },
    ]) {
      const result = await verifyIdentityAssertion({
        data: DATA,
        assertion: bad,
        publicKeyJwk: auth.jwk,
        expectedRpId: 'wallet.example',
      });
      expect(result.valid).toBe(false);
    }
    const short = await verifyIdentityAssertion({
      data: DATA,
      assertion: { ...good, authenticatorData: 'AAAA' },
      publicKeyJwk: auth.jwk,
      expectedRpId: 'wallet.example',
    });
    expect(short).toEqual({ valid: false, reason: 'MALFORMED' });
  });

  it('accepts many genuine assertions (DER integers with and without leading zeros)', async () => {
    const auth = await makeAuthenticator();
    for (let i = 0; i < 25; i++) {
      const data = `${DATA}#${i}`;
      const result = await verifyIdentityAssertion({
        data,
        assertion: await auth.assert(data),
        publicKeyJwk: auth.jwk,
        expectedRpId: 'wallet.example',
      });
      expect(result).toEqual({ valid: true });
    }
  });
});

describe('derToP1363', () => {
  it('strips a sign-padding zero and left-pads a short integer to 32 bytes', () => {
    const r = new Uint8Array(32).fill(0xff); // high bit set → DER adds a 0x00
    const s = Uint8Array.of(0x01, 0x02); // short integer → must be left-padded
    const der = Uint8Array.of(0x30, 2 + 33 + 2 + 2, 0x02, 33, 0x00, ...r, 0x02, 2, ...s);
    const raw = derToP1363(der);
    expect(raw).not.toBeNull();
    expect(raw!.length).toBe(64);
    expect(Array.from(raw!.slice(0, 32))).toEqual(Array.from(r));
    expect(Array.from(raw!.slice(32))).toEqual([...new Array(30).fill(0), 0x01, 0x02]);
  });

  it('returns null for input that is not a DER ECDSA signature', () => {
    expect(derToP1363(Uint8Array.of(1, 2, 3))).toBeNull();
  });
});

describe('spkiToP256Jwk / isUsableP256Jwk', () => {
  it('turns a registration SPKI public key into a usable P-256 JWK', async () => {
    const auth = await makeAuthenticator();
    const jwk = await spkiToP256Jwk(auth.spki);
    expect(jwk).not.toBeNull();
    expect(isUsableP256Jwk(jwk)).toBe(true);
    expect(jwk!.x).toBe(auth.jwk.x);
    expect(jwk!.y).toBe(auth.jwk.y);
  });

  it('returns null for bytes that are not a P-256 SPKI key', async () => {
    expect(await spkiToP256Jwk(Uint8Array.of(1, 2, 3).buffer)).toBeNull();
  });

  it('treats the legacy placeholder as unusable', () => {
    expect(isUsableP256Jwk({ kty: 'EC', crv: 'P-256', x: '', y: '' })).toBe(false);
    expect(isUsableP256Jwk(null)).toBe(false);
  });
});
