/**
 * @module @mitch/shared-crypto/jwe
 *
 * G-08: JWE-encrypted credentials at rest.
 *
 * Implements JWE Compact Serialization (RFC 7516) for storing credentials.
 * Algorithm: `dir` (direct encryption with symmetric CEK)
 * Encryption: `A256GCM`
 *
 * This replaces the custom IV-prefix+base64 format used in secure-storage
 * with a standards-compliant JWE token that is interoperable with any JOSE library.
 *
 * ## Usage
 * - Encrypt a credential payload before writing to IndexedDB
 * - Decrypt after reading — the JWE token is self-describing (header embedded)
 *
 * ## Security properties
 * - AES-256-GCM: authenticated encryption (confidentiality + integrity)
 * - `dir` algorithm: CEK is the storage master key (no key wrapping overhead for at-rest)
 * - For transport / multi-recipient, use ECDH-ES+A256KW (future G-08 extension)
 */

import { CompactEncrypt, compactDecrypt, type KeyLike } from 'jose';

/**
 * Encrypt a credential payload as a JWE compact token.
 *
 * @param payload - The credential object to encrypt (will be JSON-serialized)
 * @param cek - AES-256-GCM CryptoKey (the storage master key)
 * @returns JWE compact serialization string: `header.encKey.iv.ciphertext.tag`
 */
export async function encryptCredentialJWE(
  payload: Record<string, unknown>,
  cek: CryptoKey
): Promise<string> {
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  const jwe = await new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'mitch-credential+jwe' })
    .encrypt(cek as KeyLike);

  return jwe;
}

/**
 * Decrypt a JWE compact token back to the original credential payload.
 *
 * @param token - JWE compact serialization string
 * @param cek - AES-256-GCM CryptoKey (the storage master key)
 * @returns Decrypted credential object
 * @throws If decryption fails (wrong key, tampered ciphertext, invalid format)
 */
export async function decryptCredentialJWE(
  token: string,
  cek: CryptoKey
): Promise<Record<string, unknown>> {
  const { plaintext } = await compactDecrypt(token, cek as KeyLike);
  return JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
}

/**
 * Type guard: check if a stored string looks like a JWE compact token.
 * JWE compact = 5 base64url segments separated by dots.
 */
export function isJWEToken(value: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
}
