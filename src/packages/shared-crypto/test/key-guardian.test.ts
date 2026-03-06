/* eslint-disable @typescript-eslint/no-explicit-any */
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
    expect(res.keyId).toMatch(/^kg-sign-unit-test-user-/);
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
    ).rejects.toThrow(/Signing key not found/);
  });

  test('getLevel returns SOFTWARE_EPHEMERAL', async () => {
    const guardian = new SoftwareKeyGuardian();
    const level = await guardian.getLevel();

    expect(level).toBe(KeyProtectionLevel.SOFTWARE_EPHEMERAL);
  });
});

describe('G-07: Key separation — signing keys vs encryption keys', () => {
  test('createEncryptionKey returns ECDH-P256 public key without private material', async () => {
    const guardian = new SoftwareKeyGuardian();
    const res = await guardian.createEncryptionKey({ userId: 'enc-test-user' });

    expect(res.encKeyId).toMatch(/^kg-enc-enc-test-user-/);
    expect(res.publicKeyJwk.kty).toBe('EC');
    expect((res.publicKeyJwk as any).crv).toBe('P-256');
    expect((res.publicKeyJwk as any).d).toBeUndefined(); // no private material
    expect((res.publicKeyJwk as any).key_ops).not.toContain('sign'); // not a signing key
  });

  test('signing key and encryption key are stored separately — no cross-use', async () => {
    const guardian = new SoftwareKeyGuardian();
    const sigResult = await guardian.createKey({ userId: 'sep-user' });
    const encResult = await guardian.createEncryptionKey({ userId: 'sep-user' });

    // Sign with signing key — must succeed
    const data = new TextEncoder().encode('test payload');
    const sig = await guardian.sign({ keyId: sigResult.keyId, challenge: data });
    expect(sig.length).toBeGreaterThan(0);

    // Signing key ID must not work as encryption key and vice versa
    await expect(
      guardian.sign({ keyId: encResult.encKeyId, challenge: data })
    ).rejects.toThrow(/Signing key not found/);

    await expect(
      guardian.deriveSharedSecret({ encKeyId: sigResult.keyId, senderPublicKeyJwk: encResult.publicKeyJwk })
    ).rejects.toThrow(/Encryption key not found/);
  });

  test('deriveSharedSecret produces AES-256-GCM key usable for encrypt/decrypt', async () => {
    // Simulate ECDH key agreement between two parties
    const aliceGuardian = new SoftwareKeyGuardian();
    const bobGuardian = new SoftwareKeyGuardian();

    const alice = await aliceGuardian.createEncryptionKey({ userId: 'alice' });
    const bob = await bobGuardian.createEncryptionKey({ userId: 'bob' });

    // Alice derives shared secret using Bob's public key
    const aliceShared = await aliceGuardian.deriveSharedSecret({
      encKeyId: alice.encKeyId,
      senderPublicKeyJwk: bob.publicKeyJwk,
    });

    // Bob derives shared secret using Alice's public key
    const bobShared = await bobGuardian.deriveSharedSecret({
      encKeyId: bob.encKeyId,
      senderPublicKeyJwk: alice.publicKeyJwk,
    });

    // Both should produce the same shared secret — verify via encrypt/decrypt
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode('G-07: this is encrypted with ECDH shared secret');

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aliceShared,
      plaintext
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      bobShared,
      ciphertext
    );

    expect(new TextDecoder().decode(decrypted)).toBe('G-07: this is encrypted with ECDH shared secret');
  });

  test('deriveSharedSecret with unknown encKeyId throws error', async () => {
    const guardian = new SoftwareKeyGuardian();
    const other = await guardian.createEncryptionKey({ userId: 'other' });

    await expect(
      guardian.deriveSharedSecret({ encKeyId: 'missing-enc-key', senderPublicKeyJwk: other.publicKeyJwk })
    ).rejects.toThrow(/Encryption key not found/);
  });

  test('signing key ID pattern differs from encryption key ID pattern', async () => {
    const guardian = new SoftwareKeyGuardian();
    const sig = await guardian.createKey({ userId: 'pattern-user' });
    const enc = await guardian.createEncryptionKey({ userId: 'pattern-user' });

    expect(sig.keyId).toMatch(/^kg-sign-/);
    expect(enc.encKeyId).toMatch(/^kg-enc-/);
    expect(sig.keyId).not.toMatch(/^kg-enc-/);
    expect(enc.encKeyId).not.toMatch(/^kg-sign-/);
  });
});
