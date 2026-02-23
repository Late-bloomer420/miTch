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
 * Decrypt JWE payload using ephemeral private key
 * Simplified JWE decryption (ECDH-ES + A256GCM)
 */
export async function decryptJWE(
    jwe: string,
    privateKey: CryptoKey
): Promise<string> {
    // Note: Full JWE implementation requires JOSE library
    // For PoC, we assume wallet sends simple base64-encoded encrypted data
    // In production, use `jose` library for proper JWE handling

    // TODO: Implement full JWE decryption with ECDH-ES
    // For now, return placeholder
    throw new Error('JWE decryption not yet implemented (use JOSE library)');
}

// ---- Utility Functions ----

function bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuffer(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
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
