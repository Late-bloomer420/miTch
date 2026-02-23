/**
 * @mitch/predicates - Canonical Hashing
 * 
 * Hash computation for predicates and requests.
 * Uses WebCrypto (async) with Node.js crypto fallback (sync).
 */

import {
    Predicate,
    PredicateRequest,
    canonicalizePredicate,
    canonicalizeRequest
} from '@mitch/shared-types';

/**
 * Deterministically stringifies an object by sorting keys.
 * Used for signing JSON payloads.
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
        throw new Error('CANONICAL_STRINGIFY_TOPLEVEL_UNDEFINED');
    }
    return out;
}

export type {
    Predicate,
    PredicateRequest,
    PredicateClause,
    PredicateExpression,
    PredicateOp,
    PredicateValueType
} from '@mitch/shared-types';

export { canonicalizePredicate, canonicalizeRequest };

// ============================================================================
// HASHING (sync for Node, async for WebCrypto)
// ============================================================================

let hashFnSync: ((data: string) => string) | null = null;

try {
    // Attempt standard require for Node.js contexts
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const req = (typeof require !== 'undefined') ? require : null;
    if (req) {
        const crypto = req('crypto');
        hashFnSync = (data: string) => crypto.createHash('sha256').update(data).digest('hex');
    }
} catch {
    hashFnSync = null;
}

export function hashPredicate(predicate: Predicate): string {
    if (!hashFnSync) {
        throw new Error('Sync hashing not available. Use hashPredicateAsync().');
    }
    const canonical = canonicalizePredicate(predicate);
    return 'sha256:' + hashFnSync(canonical);
}

export function hashRequest(request: PredicateRequest): string {
    if (!hashFnSync) {
        throw new Error('Sync hashing not available. Use hashRequestAsync().');
    }
    const canonical = canonicalizeRequest(request);
    return 'sha256:' + hashFnSync(canonical);
}

export function sha256(data: string): string {
    if (!hashFnSync) {
        throw new Error('Sync hashing not available. Use sha256Async().');
    }
    return 'sha256:' + hashFnSync(data);
}

// ============================================================================
// ASYNC VERSIONS (Browser/WebCrypto compatible)
// ============================================================================

export async function sha256Async(data: string): Promise<string> {
    if (typeof globalThis.crypto?.subtle?.digest === 'function') {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return 'sha256:' + hashHex;
    }
    return sha256(data);
}

export async function hashPredicateAsync(predicate: Predicate): Promise<string> {
    const canonical = canonicalizePredicate(predicate);
    return sha256Async(canonical);
}

export async function hashRequestAsync(request: PredicateRequest): Promise<string> {
    const canonical = canonicalizeRequest(request);
    return sha256Async(canonical);
}
