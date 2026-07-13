import { describe, it, expect, vi, afterEach } from 'vitest';
import { WebAuthnService } from '../src/webauthn';

/**
 * F-16 / F-18: savePasskeyMeta() and saveIdentityKeyMeta() must be fail-closed.
 *
 * If IndexedDB is unavailable (or errors), registration must REJECT — not resolve
 * silently. Previously both functions swallowed DB errors in empty catch blocks,
 * reporting success even though metadata was never persisted.
 *
 * These tests require an environment mock because in the Node test env
 * isWebAuthnAvailable() returns false, causing registerPasskey / registerIdentityKey
 * to hit the early software-fallback return before ever reaching the save functions.
 * We mock WebAuthn as available + make indexedDB.open error to reach the save path.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/**
 * Sets up globals so that:
 *   - isWebAuthnAvailable() returns true (navigator.credentials.get is a function + PublicKeyCredential defined)
 *   - navigator.credentials.create() resolves with a minimal fake credential
 *   - indexedDB.open() fires onerror → getPasskeyDB() rejects → save functions catch the rejection
 */
function forceWebAuthnAvailableWithFailingIDB() {
  // isWebAuthnAvailable() checks: navigator.credentials.get is a function + PublicKeyCredential defined
  vi.stubGlobal('navigator', {
    credentials: {
      get: () => {},
      create: vi.fn().mockResolvedValue({
        rawId: new Uint8Array([1, 2, 3]).buffer,
        response: {
          getPublicKey: () => null,
        },
      }),
    },
  });
  vi.stubGlobal('PublicKeyCredential', function () {});

  // Provide a minimal location so rpId defaults work
  vi.stubGlobal('location', { hostname: 'localhost', origin: 'https://localhost' });

  // getPasskeyDB() calls indexedDB.open(...) → we fire onerror to make it reject
  vi.stubGlobal('indexedDB', {
    open: () => {
      const req: any = {};
      setTimeout(
        () => req.onerror && req.onerror({ target: { error: new Error('IDB unavailable') } }),
        0
      );
      return req;
    },
  });
}

describe('WebAuthn metadata save is fail-closed (F-16/F-18)', () => {
  it('registerPasskey rejects when passkey metadata cannot be persisted', async () => {
    forceWebAuthnAvailableWithFailingIDB();
    await expect(WebAuthnService.registerPasskey()).rejects.toThrow(/persist passkey metadata/i);
  });

  it('registerIdentityKey rejects when identity-key metadata cannot be persisted', async () => {
    forceWebAuthnAvailableWithFailingIDB();
    await expect(WebAuthnService.registerIdentityKey()).rejects.toThrow(
      /persist identity-key metadata/i
    );
  });
});
