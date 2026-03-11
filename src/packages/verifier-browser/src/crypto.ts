/**
 * @module @mitch/verifier-browser/crypto
 * 
 * Cryptographic utilities using WebCrypto API
 * All operations use ephemeral keys (never persisted to disk)
 */

/**
 * Generate an ephemeral ECDSA key pair (P-256)
 * Used for session-based verification (shredded on page refresh)
 */
export async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
    return await crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        true, // extractable (needed for JWK export)
        ['sign', 'verify']
    );
}

/**
 * Generate a cryptographic nonce (32 bytes)
 */
export function generateNonce(): string {
    const buffer = new Uint8Array(32);
    crypto.getRandomValues(buffer);
    return bufferToHex(buffer);
}

/**
 * Generate a session ID (UUID v4)
 */
export function generateSessionId(): string {
    return crypto.randomUUID();
}

/**
 * Export public key to JWK format (for wallet to encrypt response)
 */
export async function exportPublicKeyJWK(publicKey: CryptoKey): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey('jwk', publicKey);
}

/**
 * Import JWK public key from wallet
 */
export async function importPublicKeyJWK(jwk: JsonWebKey): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
        'jwk',
        jwk,
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        true,
        ['verify']
    );
}

/**
 * Verify signature using ECDSA-SHA256
 */
export async function verifySignature(
    publicKey: CryptoKey,
    data: Uint8Array,
    signature: Uint8Array
): Promise<boolean> {
    try {
        return await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            publicKey,
            signature as BufferSource,
            data as BufferSource
        );
    } catch {
        return false;
    }
}

/**
 * Compute SHA-256 hash
 */
export async function sha256(data: string | Uint8Array): Promise<string> {
    const buffer = typeof data === 'string'
        ? new TextEncoder().encode(data)
        : data;

    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as BufferSource);
    return bufferToHex(new Uint8Array(hashBuffer));
}

/**
 * Decrypt a JWE Compact Serialization using ECDH-ES + A256GCM (RFC 7516/7518).
 *
 * JWE Compact: BASE64URL(header) . "" . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)
 * (encryptedKey is empty for ECDH-ES direct key agreement)
 *
 * @param jwe    - JWE Compact Serialization string
 * @param privateKey - Receiver's ECDSA P-256 CryptoKey (re-imported as ECDH internally)
 */
export async function decryptJWE(
    jwe: string,
    privateKey: CryptoKey
): Promise<string> {
    const parts = jwe.split('.');
    if (parts.length !== 5) {
        throw new Error('JWE_DECRYPT_FAILED: not a compact JWE (expected 5 parts)');
    }
    const [encodedHeader, , encodedIv, encodedCiphertext, encodedTag] = parts;

    // 1. Parse protected header
    const header = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(encodedHeader))) as {
        alg: string;
        enc: string;
        epk?: JsonWebKey;
        apu?: string;
        apv?: string;
    };

    if (header.alg !== 'ECDH-ES') {
        throw new Error(`JWE_DECRYPT_FAILED: unsupported alg "${header.alg}" (expected ECDH-ES)`);
    }
    if (header.enc !== 'A256GCM') {
        throw new Error(`JWE_DECRYPT_FAILED: unsupported enc "${header.enc}" (expected A256GCM)`);
    }
    if (!header.epk) {
        throw new Error('JWE_DECRYPT_FAILED: missing epk in header');
    }

    // 2. Import ephemeral public key (epk) as ECDH
    const epk = await crypto.subtle.importKey(
        'jwk',
        header.epk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        [],
    );

    // 3. Re-import receiver's private key as ECDH (same P-256 curve, different algorithm label)
    const privJwk = await crypto.subtle.exportKey('jwk', privateKey);
    const ecdhPrivKey = await crypto.subtle.importKey(
        'jwk',
        { ...privJwk, key_ops: ['deriveBits'] },
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits'],
    );

    // 4. ECDH — derive shared secret Z (256 bits = 32 bytes)
    const zBuf = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: epk },
        ecdhPrivKey,
        256,
    );
    const Z = new Uint8Array(zBuf);

    // 5. CONCAT-KDF per RFC 7518 §4.6.2
    //    keydatalen = 256 bits for A256GCM
    const contentEncAlg = 'A256GCM';
    const cek = await concatKdf(Z, 256, contentEncAlg, header.apu, header.apv);

    // 6. Import CEK as AES-256-GCM
    const aesKey = await crypto.subtle.importKey(
        'raw', cek.buffer as ArrayBuffer,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
    );

    // 7. Decode iv, ciphertext, tag; concatenate ciphertext+tag for WebCrypto
    const iv = base64UrlToBuffer(encodedIv);
    const ciphertext = base64UrlToBuffer(encodedCiphertext);
    const tag = base64UrlToBuffer(encodedTag);

    // WebCrypto AES-GCM expects ciphertext || tag as a single buffer
    const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
    ciphertextWithTag.set(ciphertext, 0);
    ciphertextWithTag.set(tag, ciphertext.length);

    // AAD = ASCII bytes of the encoded header
    const aad = new TextEncoder().encode(encodedHeader);

    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, additionalData: aad.buffer as ArrayBuffer, tagLength: 128 },
        aesKey,
        ciphertextWithTag.buffer as ArrayBuffer,
    );

    return new TextDecoder().decode(plaintext);
}

/**
 * CONCAT-KDF (Single-Step KDF) per RFC 7518 §4.6.2.
 *
 * Hash = SHA-256(counter(1) || Z || AlgorithmID || PartyUInfo || PartyVInfo || keydatalen)
 * where each field is prefixed with a big-endian 4-byte length (except counter and keydatalen).
 */
async function concatKdf(
    Z: Uint8Array,
    keydatalenBits: number,
    algId: string,
    apuB64?: string,
    apvB64?: string,
): Promise<Uint8Array> {
    const enc = new TextEncoder();

    function lengthPrefixed(data: Uint8Array): Uint8Array {
        const out = new Uint8Array(4 + data.length);
        new DataView(out.buffer).setUint32(0, data.length, false);
        out.set(data, 4);
        return out;
    }

    function uint32BE(n: number): Uint8Array {
        const buf = new Uint8Array(4);
        new DataView(buf.buffer).setUint32(0, n, false);
        return buf;
    }

    const algIdBytes = enc.encode(algId);
    const apu = apuB64 ? base64UrlToBuffer(apuB64) : new Uint8Array(0);
    const apv = apvB64 ? base64UrlToBuffer(apvB64) : new Uint8Array(0);

    const otherInfo = [
        lengthPrefixed(algIdBytes),
        lengthPrefixed(apu),
        lengthPrefixed(apv),
        uint32BE(keydatalenBits),
    ];

    // Single iteration: counter = 1 (keydatalen ≤ 256 bits → one SHA-256 block)
    const parts = [uint32BE(1), Z, ...otherInfo];
    const totalLen = parts.reduce((s, p) => s + p.length, 0);
    const input = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) { input.set(p, offset); offset += p.length; }

    const hashBuf = await crypto.subtle.digest('SHA-256', input);
    // Return first keydatalenBits/8 bytes
    return new Uint8Array(hashBuf).slice(0, keydatalenBits / 8);
}

// ---- Utility Functions ----

function bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

export function base64UrlToBuffer(base64url: string): Uint8Array {
    // Convert base64url to base64
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (base64.length % 4)) % 4);
    const binaryString = atob(base64 + padding);

    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

export function bufferToBase64Url(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
