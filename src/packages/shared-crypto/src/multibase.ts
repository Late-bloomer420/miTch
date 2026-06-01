/**
 * @module @mitch/shared-crypto/multibase
 * 
 * Multibase and Multihash Utilities
 * 
 * Supports:
 * - base58btc (prefix 'z')
 * - SHA-256 multihash (prefix 0x12 0x20)
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode bytes to base58btc string with 'z' prefix.
 */
export function encodeBase58btc(bytes: Uint8Array): string {
    return 'z' + base58Encode(bytes);
}

/**
 * Decode base58btc string (must start with 'z').
 */
export function decodeBase58btc(str: string): Uint8Array {
    if (!str.startsWith('z')) {
        throw new Error(`MULTIBASE_INVALID_ENCODING: expected base58btc (prefix 'z'), got ${str[0]}`);
    }
    return base58Decode(str.slice(1));
}

/**
 * SHA-256 multihash prefix: 0x12 (SHA-2-256) 0x20 (32 bytes length)
 */
const SHA256_MULTIHASH_PREFIX = new Uint8Array([0x12, 0x20]);

/**
 * Wrap SHA-256 hash bytes in a multihash structure.
 */
export function wrapSha256Multihash(hashBytes: Uint8Array): Uint8Array {
    if (hashBytes.length !== 32) {
        throw new Error(`MULTIHASH_INVALID_LENGTH: expected 32 bytes for SHA-256, got ${hashBytes.length}`);
    }
    const multihash = new Uint8Array(2 + 32);
    multihash.set(SHA256_MULTIHASH_PREFIX);
    multihash.set(hashBytes, 2);
    return multihash;
}

/**
 * Unwrap SHA-256 multihash and return raw hash bytes.
 */
export function unwrapSha256Multihash(multihash: Uint8Array): Uint8Array {
    if (multihash.length !== 34 || multihash[0] !== 0x12 || multihash[1] !== 0x20) {
        throw new Error('MULTIHASH_INVALID_FORMAT: expected SHA-256 multihash (0x12 0x20 prefix, 34 bytes)');
    }
    return multihash.slice(2);
}

// ─── Base58 Internal Helpers ───────────────────────────────────────────────────

export function base58Encode(bytes: Uint8Array): string {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    
    let result = '';
    while (n > 0n) {
        result = BASE58_ALPHABET[Number(n % 58n)] + result;
        n /= 58n;
    }
    for (const b of bytes) {
        if (b !== 0) break;
        result = '1' + result;
    }
    return result;
}

export function base58Decode(str: string): Uint8Array {
    let n = 0n;
    for (const c of str) {
        const idx = BASE58_ALPHABET.indexOf(c);
        if (idx === -1) throw new Error(`Invalid base58 char: ${c}`);
        n = n * 58n + BigInt(idx);
    }
    let leadingZeros = 0;
    for (const c of str) {
        if (c !== '1') break;
        leadingZeros++;
    }
    const bytes: number[] = [];
    while (n > 0n) {
        bytes.unshift(Number(n & 0xffn));
        n >>= 8n;
    }
    const result = new Uint8Array(leadingZeros + bytes.length);
    result.set(bytes, leadingZeros);
    return result;
}
