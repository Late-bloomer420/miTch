/**
 * @module @mitch/shared-crypto/encryption
 * 
 * AES-256-GCM Encryption Module
 * 
 * Provides authenticated encryption and decryption using the Web Crypto API.
 * 
 * ## Features
 * - AES-256-GCM with random 96-bit IV
 * - Optional AAD (Additional Authenticated Data) binding
 * - Ciphertext stored as base64 with IV prefix
 * - Constant-time operations where possible
 * 
 * ## Security Properties
 * - Confidentiality: 256-bit AES encryption
 * - Integrity: GCM authentication tag
 * - Context Binding: AAD ties ciphertext to specific context
 */

import { crypto } from './platform';

/**
 * Robust Base64 implementation for binary data.
 */

function toBase64(bytes: Uint8Array): string {
    const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
    return btoa(binString);
}

function fromBase64(b64: string): Uint8Array {
    try {
        // Remove whitespace which can be present in stored strings
        const cleanB64 = b64.replace(/\s/g, '');
        const binString = atob(cleanB64);
        return Uint8Array.from(binString, (m) => m.charCodeAt(0));
    } catch (e) {
        throw new Error(`Base64 decoding failed: ${e instanceof Error ? e.message : 'Invalid characters'}`);
    }
}

/**
 * Normalizes a BufferSource (Uint8Array or ArrayBuffer) to a pure ArrayBuffer.
 * This resolves issues where TS 5.x infers SharedArrayBuffer-compatible views.
 */
function normalizeToBuffer(source: BufferSource): ArrayBuffer {
    if (source instanceof ArrayBuffer) return source;
    // It's an ArrayBufferView (e.g. Uint8Array)
    return source.buffer.slice(
        source.byteOffset,
        source.byteOffset + source.byteLength
    );
}

/**
 * Encrypt a UTF-8 string with AES-256-GCM.
 */
export async function encrypt(
    plaintext: string,
    key: CryptoKey,
    aad?: BufferSource
): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();

    const alg: AesGcmParams = aad
        ? {
            name: 'AES-GCM',
            iv: normalizeToBuffer(iv),
            additionalData: normalizeToBuffer(aad)
        }
        : {
            name: 'AES-GCM',
            iv: normalizeToBuffer(iv)
        };

    const ct = await crypto.subtle.encrypt(alg, key, enc.encode(plaintext));

    const combined = new Uint8Array(iv.byteLength + ct.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ct), iv.byteLength);

    return toBase64(combined);
}

/**
 * Decrypt data produced by `encrypt`.
 */
export async function decrypt(
    data: string,
    key: CryptoKey,
    aad?: BufferSource
): Promise<string> {
    const combined = fromBase64(data);

    // Safety check for legacy or corrupted data
    if (combined.byteLength < 13) {
        throw new Error('CORRUPTION_DETECTED: Ciphertext too short (Legacy payload?)');
    }

    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const alg: AesGcmParams = aad
        ? {
            name: 'AES-GCM',
            iv: normalizeToBuffer(iv),
            additionalData: normalizeToBuffer(aad)
        }
        : {
            name: 'AES-GCM',
            iv: normalizeToBuffer(iv)
        };

    try {
        const pt = await crypto.subtle.decrypt(alg, key, ciphertext);
        return new TextDecoder().decode(pt);
    } catch (e) {
        throw new Error(`DECRYPTION_FAILED: Authentication tag mismatch or wrong AAD binding.`);
    }
}
