/**
 * @module @mitch/shared-crypto/hashing
 * 
 * Cryptographic Hashing Utilities
 * 
 * Provides hash functions and canonical serialization for:
 * - SHA-256 hashing of strings
 * - HMAC-SHA-256 for keyed authentication
 * - Canonical JSON stringification for stable hashing
 * 
 * All hash outputs are returned as lowercase hex strings.
 */

import { crypto } from './platform';

/**
 * SHA-256 hash of a UTF-8 string, returned as hex.
 */
export async function sha256(message: string): Promise<string> {
    const enc = new TextEncoder();
    const data = enc.encode(message);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return toHex(new Uint8Array(hash));
}

/**
 * HMAC-SHA-256 – returns a hex string.
 *
 * @param key CryptoKey (must be usable for `sign`)
 * @param data UTF-8 string
 */
export async function hmac(key: CryptoKey, data: string): Promise<string> {
    const enc = new TextEncoder();
    const signature = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    return toHex(new Uint8Array(signature));
}

/**
 * Stable, canonical JSON stringify.
 * Recursively sorts keys and handles arrays/nulls to ensure stable hashing and AAD.
 * 
 * SEMANTICS (Drop-in Robust):
 * - undefined in Objects -> key omitted
 * - undefined in Arrays -> 'null'
 * - Date -> ISO String (quoted)
 * - BigInt -> ERROR (Fail-Closed)
 * - Keys -> JSON.stringify(key) to ensure escaping
 */
export function canonicalStringify(value: unknown): string {
    const seen = new Set<object>();

    const helper = (v: any, inArray: boolean): string | undefined => {
        // JSON.stringify semantics for "non-serializable"
        if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
            return inArray ? 'null' : undefined; // skip in objects, null in arrays
        }
        if (typeof v === 'bigint') {
            throw new Error('CANONICAL_STRINGIFY_UNSUPPORTED: bigint');
        }
        if (v === null) return 'null';
        if (typeof v !== 'object') return JSON.stringify(v);

        // Dates: fail-closed determinism
        if (v instanceof Date) {
            return JSON.stringify(v.toISOString());
        }

        if (seen.has(v)) throw new Error('CANONICAL_STRINGIFY_CYCLE');
        seen.add(v);

        if (Array.isArray(v)) {
            const items = v.map((item) => {
                const s = helper(item, true);
                return s ?? 'null';
            });
            seen.delete(v);
            return `[${items.join(',')}]`;
        }

        // Plain object: sort keys, skip undefined-like
        const keys = Object.keys(v).sort();
        const parts: string[] = [];
        for (const k of keys) {
            const sv = helper(v[k], false);
            if (sv === undefined) continue; // omit key
            // JSON.stringify the key to ensure proper escaping of quotes/controls
            parts.push(`${JSON.stringify(k)}:${sv}`);
        }
        seen.delete(v);
        return `{${parts.join(',')}}`;
    };

    const out = helper(value as any, false);
    // Top-level undefined becomes undefined in JSON.stringify; for signing we fail logic
    if (out === undefined) {
        // Technically this should throw for a signature base, but to be safe/compatible with strict typing:
        throw new Error('CANONICAL_STRINGIFY_TOPLEVEL_UNDEFINED');
    }
    return out;
}

/**
 * Helper to convert Uint8Array to hex string (browser safe).
 */
export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
