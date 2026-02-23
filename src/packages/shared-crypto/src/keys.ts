/**
 * @module @mitch/shared-crypto/keys
 * 
 * Cryptographic Key Management
 * 
 * Provides functions for generating, deriving, and wrapping cryptographic keys:
 * - ECDSA P-256 key pairs for signing/verification
 * - AES-256-GCM symmetric keys for encryption
 * - PBKDF2 key derivation from passphrases
 * - RSA-OAEP key wrapping for secure key transport
 * 
 * All keys are generated as non-extractable by default to prevent exposure.
 */

import { crypto } from './platform';

/**
 * Normalizes a BufferSource (Uint8Array or ArrayBuffer) to a pure ArrayBuffer.
 */
function normalizeToBuffer(source: BufferSource): ArrayBuffer {
    if (source instanceof ArrayBuffer) return source;
    return source.buffer.slice(
        source.byteOffset,
        source.byteOffset + source.byteLength
    );
}

/**
 * Generate an asymmetric ECDSA‑P‑256 key pair.
 * The private key is non‑extractable (cannot be exported) – ideal for
 * Ephemeral‑Key‑use‑cases.
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        false, // not extractable
        ['sign', 'verify']
    );
}

/**
 * Generate a symmetric AES‑256‑GCM key.
 * @param extractable Whether the key can be exported/wrapped (default: false)
 */
export async function generateSymmetricKey(extractable: boolean = false): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256,
        },
        extractable,
        ['encrypt', 'decrypt']
    );
}

/**
 * Derive a symmetric key from a password using PBKDF2.
 *
 * @param password UTF‑8 password string
 * @param salt BufferSource (at least 16 bytes recommended)
 * @param iterations number of PBKDF2 iterations (default = 100 000)
 */
export async function deriveKeyFromPassword(
    password: string,
    salt: BufferSource,
    iterations = 100_000
): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: normalizeToBuffer(salt),
            iterations,
            hash: 'SHA-256',
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Wraps (encrypts) a symmetric key for a specific recipient using their public key.
 * Currently uses RSA-OAEP for simplicity in PoC (assuming Verifiers have RSA keys).
 * In production, this should support ECDH (X25519) + HKDF.
 *
 * @param receiverPublicKey The recipient's public key (RSA-OAEP)
 * @param keyToWrap The symmetric key to encrypt (AES-GCM)
 */
export async function wrapKeyForRecipient(
    receiverPublicKey: CryptoKey,
    keyToWrap: CryptoKey
): Promise<string> {
    const wrapped = await crypto.subtle.wrapKey(
        'raw',
        keyToWrap,
        receiverPublicKey,
        { name: 'RSA-OAEP' }
    );
    // Convert ArrayBuffer to base64 without Buffer (browser safe)
    const bytes = new Uint8Array(wrapped);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

