import 'fake-indexeddb/auto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ASKMI_STORAGE_KEYS } from '@askmi/shared-types';
import { WebAuthnService } from '../src/webauthn';
import { isUsableP256Jwk, verifyIdentityAssertion } from '../src/webauthn-assertion';
import { fakePlatformAuthenticator } from './helpers/fake-authenticator';

/**
 * PR 1 of the verifiable-passkey work: registration keeps the real public key,
 * and the new assertion signer returns everything needed to verify a hardware
 * identity signature. Existing signWithIdentityKey() behaviour is unchanged.
 */

function useAuthenticator(credentials: unknown) {
  vi.stubGlobal('PublicKeyCredential', class {});
  vi.stubGlobal('navigator', { credentials });
  vi.stubGlobal('location', { hostname: 'wallet.example', origin: 'https://wallet.example' });
}

async function writeLegacyPlaceholderRegistration() {
  const legacy = {
    credentialId: 'CQgHBg',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: '', y: '', alg: 'ES256', ext: true },
    rpId: 'wallet.example',
    registeredAt: '2026-07-01T00:00:00.000Z',
  };
  await new Promise<void>((resolve, reject) => {
    const open = indexedDB.open(ASKMI_STORAGE_KEYS.passkeyDb, 1);
    open.onupgradeneeded = () => open.result.createObjectStore('passkeys');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('passkeys', 'readwrite');
      tx.objectStore('passkeys').put(
        JSON.stringify(legacy),
        ASKMI_STORAGE_KEYS.identityKeyRegistration
      );
      tx.oncomplete = () => {
        open.result.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    };
  });
}

beforeEach(async () => {
  await WebAuthnService.clearRegistration();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('registerIdentityKey keeps the real public key', () => {
  it('stores the P-256 public key from the registration response', async () => {
    const auth = await fakePlatformAuthenticator();
    useAuthenticator(auth.credentials);

    const registration = await WebAuthnService.registerIdentityKey('wallet.example');

    expect(isUsableP256Jwk(registration.publicKeyJwk)).toBe(true);
    expect(registration.publicKeyJwk!.x).toBe(auth.jwk.x);
    expect(registration.publicKeyJwk!.y).toBe(auth.jwk.y);
    expect(await WebAuthnService.getIdentityPublicKeyJwk()).toEqual(registration.publicKeyJwk);
  });

  it('stores no key when the authenticator does not expose one', async () => {
    const auth = await fakePlatformAuthenticator({ exposePublicKey: false });
    useAuthenticator(auth.credentials);

    const registration = await WebAuthnService.registerIdentityKey('wallet.example');

    expect(registration.publicKeyJwk).toBeNull();
    expect(await WebAuthnService.getIdentityPublicKeyJwk()).toBeNull();
  });

  it('treats a legacy placeholder registration (empty x/y) as having no public key', async () => {
    await writeLegacyPlaceholderRegistration();
    expect(await WebAuthnService.getIdentityPublicKeyJwk()).toBeNull();
    expect(await WebAuthnService.isIdentityRegistered()).toBe(true);
  });
});

describe('getIdentityVerificationKey', () => {
  it('returns the registered rpId with the stored public key', async () => {
    const auth = await fakePlatformAuthenticator();
    useAuthenticator(auth.credentials);
    await WebAuthnService.registerIdentityKey('wallet.example');

    const key = await WebAuthnService.getIdentityVerificationKey();

    expect(key?.rpId).toBe('wallet.example');
    expect(key?.publicKeyJwk?.x).toBe(auth.jwk.x);
  });

  it('returns the rpId with a null key for a legacy placeholder registration', async () => {
    await writeLegacyPlaceholderRegistration();
    expect(await WebAuthnService.getIdentityVerificationKey()).toEqual({
      rpId: 'wallet.example',
      publicKeyJwk: null,
    });
  });

  it('returns null without a hardware registration', async () => {
    expect(await WebAuthnService.getIdentityVerificationKey()).toBeNull();
  });
});

describe('signWithIdentityKeyAssertion', () => {
  it('returns an assertion that verifies against the stored public key', async () => {
    const auth = await fakePlatformAuthenticator();
    useAuthenticator(auth.credentials);
    await WebAuthnService.registerIdentityKey('wallet.example');
    const data = '{"hash":"abc","purpose":"erasure"}';

    const assertion = await WebAuthnService.signWithIdentityKeyAssertion(data);

    expect(assertion).toMatchObject({ version: 1, rpId: 'wallet.example', credentialId: 'CQgHBg' });
    const result = await verifyIdentityAssertion({
      data,
      assertion,
      publicKeyJwk: await WebAuthnService.getIdentityPublicKeyJwk(),
      expectedRpId: 'wallet.example',
      expectedOrigin: 'https://wallet.example',
    });
    expect(result).toEqual({ valid: true });
  });

  it('uses SHA-256 of the data as the challenge, also for short data', async () => {
    const auth = await fakePlatformAuthenticator();
    const get = vi.fn(auth.credentials.get);
    useAuthenticator({ ...auth.credentials, get });
    await WebAuthnService.registerIdentityKey('wallet.example');

    await WebAuthnService.signWithIdentityKeyAssertion('hi');

    const challenge = new Uint8Array(get.mock.calls[0][0].publicKey.challenge as ArrayBuffer);
    const expected = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('hi'))
    );
    expect(Array.from(challenge)).toEqual(Array.from(expected));
  });

  it('refuses without a registered hardware identity key, even where WebAuthn is unavailable', async () => {
    // Node: no navigator.credentials → the legacy signer would use the software fallback.
    await expect(WebAuthnService.signWithIdentityKeyAssertion('payload')).rejects.toThrow(
      /IDENTITY_KEY_NOT_REGISTERED/
    );
  });

  it('leaves signWithIdentityKey (bare signature) unchanged for existing callers', async () => {
    const auth = await fakePlatformAuthenticator();
    useAuthenticator(auth.credentials);
    await WebAuthnService.registerIdentityKey('wallet.example');

    const legacy = await WebAuthnService.signWithIdentityKey('payload');
    expect(typeof legacy).toBe('string');
    expect(legacy).toMatch(/^[A-Za-z0-9+/]+=*$/); // standard base64, as before
  });
});
