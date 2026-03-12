/**
 * G-08: JWE encrypted credentials at rest.
 * Tests for encryptCredentialJWE / decryptCredentialJWE using JWE compact serialization.
 */
import { describe, test, expect, beforeAll } from 'vitest';
import { encryptCredentialJWE, decryptCredentialJWE, isJWEToken } from '../src/jwe';

let cek: CryptoKey;

beforeAll(async () => {
  cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
});

describe('G-08: JWE credential encryption', () => {
  test('encryptCredentialJWE produces a valid JWE compact token (5 segments)', async () => {
    const payload = { credentialType: 'AgeCredential', age: 25 };
    const token = await encryptCredentialJWE(payload, cek);

    expect(typeof token).toBe('string');
    const parts = token.split('.');
    expect(parts).toHaveLength(5); // header.encKey.iv.ciphertext.tag
    expect(isJWEToken(token)).toBe(true);
  });

  test('decryptCredentialJWE round-trips the original payload', async () => {
    const payload = {
      credentialType: 'HealthCredential',
      subject: 'did:example:patient',
      claims: { diagnosis: 'confidential' },
    };

    const token = await encryptCredentialJWE(payload, cek);
    const decrypted = await decryptCredentialJWE(token, cek);

    expect(decrypted).toEqual(payload);
  });

  test('JWE header declares alg=dir enc=A256GCM (self-describing)', async () => {
    const token = await encryptCredentialJWE({ test: true }, cek);
    const headerB64 = token.split('.')[0];
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));

    expect(header.alg).toBe('dir');
    expect(header.enc).toBe('A256GCM');
    expect(header.typ).toBe('mitch-credential+jwe');
  });

  test('JWE ciphertext does not contain plaintext fields (no PII leakage)', async () => {
    const payload = { subject: 'did:example:secret-patient', birthDate: '1990-01-01' };
    const token = await encryptCredentialJWE(payload, cek);

    // Raw token must not contain any plaintext PII values
    expect(token).not.toContain('secret-patient');
    expect(token).not.toContain('1990-01-01');
    expect(token).not.toContain('birthDate');
  });

  test('decryptCredentialJWE throws or returns wrong data on wrong key', async () => {
    const wrongKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const original = { data: 'secret' };
    const token = await encryptCredentialJWE(original, cek);

    // AES-GCM with wrong key should throw (authentication tag mismatch).
    // In rare edge cases the JOSE lib may not throw but return garbage — either way
    // the original payload must NOT be recoverable.
    try {
      const result = await decryptCredentialJWE(token, wrongKey);
      // If it didn't throw, the result must NOT equal the original payload
      expect(result).not.toEqual(original);
    } catch {
      // Expected: decryption fails — test passes
    }
  });

  test('decryptCredentialJWE throws or returns wrong data on tampered ciphertext', async () => {
    const original = { data: 'secret' };
    const token = await encryptCredentialJWE(original, cek);
    const parts = token.split('.');
    // Aggressively corrupt ciphertext: reverse the entire segment
    parts[3] = parts[3].split('').reverse().join('');
    const tampered = parts.join('.');

    // AES-GCM should reject tampered data. In edge cases the JOSE lib
    // may not throw but return garbage — either way original must not leak.
    try {
      const result = await decryptCredentialJWE(tampered, cek);
      expect(result).not.toEqual(original);
    } catch {
      // Expected: decryption fails — test passes
    }
  });

  test('isJWEToken correctly identifies JWE vs plaintext', async () => {
    const token = await encryptCredentialJWE({ x: 1 }, cek);
    expect(isJWEToken(token)).toBe(true);
    expect(isJWEToken('not-a-jwe')).toBe(false);
    expect(isJWEToken('{"plain":"json"}')).toBe(false);
    // 4 segments (JWS) is not JWE
    expect(isJWEToken('a.b.c.d')).toBe(false);
  });

  test('each encryption produces a unique token (random IV)', async () => {
    const payload = { data: 'same' };
    const t1 = await encryptCredentialJWE(payload, cek);
    const t2 = await encryptCredentialJWE(payload, cek);

    expect(t1).not.toBe(t2); // different IV each time
    // But both decrypt to same value
    expect(await decryptCredentialJWE(t1, cek)).toEqual(payload);
    expect(await decryptCredentialJWE(t2, cek)).toEqual(payload);
  });
});
