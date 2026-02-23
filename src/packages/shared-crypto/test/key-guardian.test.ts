import { describe, test, expect, beforeAll } from 'vitest';
import { SoftwareKeyGuardian } from '../src/SoftwareKeyGuardian';
import { KeyProtectionLevel } from '../src/types/KeyProtectionLevel';

// Ensure browser-only globals exist in Node test env
beforeAll(() => {
  if (!(globalThis as any).btoa) {
    (globalThis as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
  }
  // Node 20+ exposes globalThis.crypto with WebCrypto; if not, fail fast
  expect(globalThis.crypto && (globalThis.crypto as any).subtle).toBeDefined();
});

describe('SoftwareKeyGuardian', () => {
  test('createKey returns public JWK without private material', async () => {
    const guardian = new SoftwareKeyGuardian();
    const res = await guardian.createKey({ userId: 'unit-test-user' });

    expect(res.level).toBe(KeyProtectionLevel.SOFTWARE_EPHEMERAL);
    expect(res.publicKeyJwk.kty).toBe('EC');
    expect((res.publicKeyJwk as any).crv).toBe('P-256');
    expect((res.publicKeyJwk as any).d).toBeUndefined(); // no private material
    expect(res.keyId).toMatch(/^kg-unit-test-user-/);
  });

  test('sign produces valid ECDSA signature, verify with WebCrypto', async () => {
    const guardian = new SoftwareKeyGuardian();
    const res = await guardian.createKey({ userId: 'test-user' });

    const data = new TextEncoder().encode('hello world');
    const signature = await guardian.sign({ keyId: res.keyId, challenge: data });

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBeGreaterThan(0);

    // Verify signature using WebCrypto
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      res.publicKeyJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );

    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      data
    );
    expect(valid).toBe(true);
  });

  test('sign with unknown keyId throws error', async () => {
    const guardian = new SoftwareKeyGuardian();
    const data = new TextEncoder().encode('payload');
    
    await expect(
      guardian.sign({ keyId: 'missing-key', challenge: data })
    ).rejects.toThrow(/Key not found/);
  });

  test('getLevel returns SOFTWARE_EPHEMERAL', async () => {
    const guardian = new SoftwareKeyGuardian();
    const level = await guardian.getLevel();
    
    expect(level).toBe(KeyProtectionLevel.SOFTWARE_EPHEMERAL);
  });
});
