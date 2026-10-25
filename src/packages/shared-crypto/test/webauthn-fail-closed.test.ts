import { describe, it, expect, vi, afterEach } from 'vitest';
import { WebAuthnService } from '../src/webauthn';

/**
 * Fail-closed invariant for the hardware-bound identity key.
 *
 * The "real secure key" is the WebAuthn/passkey identity key. The software
 * fallback exists ONLY for environments where WebAuthn is unavailable
 * (Node/tests/legacy browsers). It must NEVER be reachable as an
 * error-recovery or missing-key path when WebAuthn IS available — otherwise a
 * caller could obtain a software-signed "presence proof" that is
 * indistinguishable from a real one, silently bypassing the secure key.
 *
 * This directly enforces the North-Star Fail-Closed invariant.
 */

/** Make isWebAuthnAvailable() return true and drive navigator.credentials. */
function stubWebAuthnAvailable(getImpl: () => Promise<unknown>) {
  vi.stubGlobal('PublicKeyCredential', class {});
  vi.stubGlobal('navigator', {
    credentials: {
      get: vi.fn(getImpl),
      create: vi.fn(async () => {
        throw new Error('not used');
      }),
    },
  });
  vi.stubGlobal('location', { hostname: 'example.com', origin: 'https://example.com' });
  // indexedDB intentionally left undefined → no registered identity key.
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('WebAuthn fail-closed: no silent software downgrade when WebAuthn is available', () => {
  it('provePresenceDetailed THROWS on an unexpected assertion error instead of returning a software fallback', async () => {
    stubWebAuthnAvailable(async () => {
      const err = new Error('device exploded');
      err.name = 'AbortError'; // not NotAllowed/Security/InvalidState/NotSupported
      throw err;
    });

    await expect(WebAuthnService.provePresenceDetailed('decision-123')).rejects.toThrow();
  });

  it('signWithIdentityKey THROWS when WebAuthn is available but no identity key is registered', async () => {
    stubWebAuthnAvailable(async () => {
      throw new Error('should not be called');
    });

    await expect(WebAuthnService.signWithIdentityKey('payload-abc')).rejects.toThrow();
  });
});

describe('WebAuthn software fallback still works when WebAuthn is UNAVAILABLE (Node/test)', () => {
  it('signWithIdentityKey returns a software signature when navigator.credentials is absent', async () => {
    // No stubbing: Node/vitest has no navigator.credentials → isWebAuthnAvailable() === false.
    const sig = await WebAuthnService.signWithIdentityKey('payload-node');
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
  });
});

describe('F-03: verifyPresence() retired false-success stub', () => {
  it('rejects with a "retired" / "must not be used" error instead of resolving true', async () => {
    await expect(
      WebAuthnService.verifyPresence('decision-abc', 'any-non-empty-attestation'),
    ).rejects.toThrow(/retired|must not be used/i);
  });

  it('rejects even when attestation is empty', async () => {
    await expect(WebAuthnService.verifyPresence('decision-abc', '')).rejects.toThrow(
      /retired|must not be used/i,
    );
  });
});
