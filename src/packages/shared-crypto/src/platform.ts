/**
 * Cross‑platform WebCrypto abstraction.
 *
 * In the browser `globalThis.crypto` is the native WebCrypto API.
 * In Node we fall back to the bundled WebCrypto implementation
 * (`require('crypto').webcrypto`).
 */
export const crypto: Crypto = (() => {
    if (typeof globalThis.crypto !== 'undefined') {
        return globalThis.crypto;
    }

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require('crypto').webcrypto;
    return nodeCrypto;
})();

/**
 * Probe that the required WebCrypto algorithms are available on this platform.
 * Call once at application startup; throws with a descriptive message on failure.
 *
 * Required algorithms: AES-GCM (256), ECDSA P-256 (SHA-256), HKDF.
 * F-17 fix: previously only `globalThis.crypto` existence was checked.
 */
export async function assertCryptoCapabilities(): Promise<void> {
    // AES-GCM — symmetric encryption of stored credentials
    await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    ).catch(() => { throw new Error('CRYPTO_UNAVAILABLE: AES-GCM-256 not supported on this platform'); });

    // ECDSA P-256 — signing / DID operations
    await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
    ).catch(() => { throw new Error('CRYPTO_UNAVAILABLE: ECDSA P-256 not supported on this platform'); });

    // HKDF — pairwise DID key derivation
    const hkdfBase = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(32),
        { name: 'HKDF' },
        false,
        ['deriveBits'],
    ).catch(() => { throw new Error('CRYPTO_UNAVAILABLE: HKDF not supported on this platform'); });

    await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new Uint8Array(0) },
        hkdfBase,
        256,
    ).catch(() => { throw new Error('CRYPTO_UNAVAILABLE: HKDF deriveBits failed on this platform'); });
}
