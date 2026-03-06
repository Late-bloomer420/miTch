/**
 * @module @mitch/shared-crypto/did
 * 
 * Decentralized Identifier (DID) Resolution & Key Extraction
 * 
 * Implements:
 * - did:web resolution (Production-Standard, HTTPS)
 * - did:mitch resolution (Demo Backend)
 * - did:peer:0 resolution (U-02: Inline, no network — Spec 111)
 * - Verification key extraction from DID Documents
 * - Configurable TTL cache with fail-closed semantics
 * - Mock fallback (Development only)
 * 
 * SECURITY: Fail-closed — any resolution or key extraction failure = DENY
 */

import { DIDDocument } from '@mitch/shared-types';
import { importJWK } from 'jose';
import type { KeyLike, JWK } from 'jose';
import { resolveDidPeer0 } from './pairwise-did';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface DIDResolverOptions {
    /** Cache TTL in milliseconds (default: 1 hour) */
    cacheTtlMs?: number;
    /** Fetch timeout in milliseconds (default: 10 seconds) */
    fetchTimeoutMs?: number;
    /** Custom fetch function (for testing) */
    fetchFn?: typeof fetch;
    /** Allow mock fallback for unknown DID methods (default: false — DENY) */
    allowMockFallback?: boolean;
    /** Allow insecure did:web localhost/http resolution (default: false — DENY) */
    allowInsecureLocalhostDidWeb?: boolean;
}

export interface CachedDIDDocument {
    document: DIDDocument;
    resolvedAt: number;
    expiresAt: number;
}

export class DIDResolutionError extends Error {
    constructor(
        public readonly did: string,
        message: string,
        public readonly cause?: unknown
    ) {
        super(`DID_RESOLUTION_FAILED: ${did} — ${message}`);
        this.name = 'DIDResolutionError';
    }
}

export class DIDKeyExtractionError extends Error {
    constructor(
        public readonly did: string,
        message: string
    ) {
        super(`DID_KEY_EXTRACTION_FAILED: ${did} — ${message}`);
        this.name = 'DIDKeyExtractionError';
    }
}

// ─── DID Resolver ───────────────────────────────────────────────────────────

const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const DEFAULT_FETCH_TIMEOUT_MS = 10_000; // 10 seconds

export class DIDResolver {
    private cache = new Map<string, CachedDIDDocument>();
    private readonly cacheTtlMs: number;
    private readonly fetchTimeoutMs: number;
    private readonly fetchFn: typeof fetch;
    private readonly allowMockFallback: boolean;
    private readonly allowInsecureLocalhostDidWeb: boolean;

    constructor(options: DIDResolverOptions = {}) {
        this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
        this.fetchTimeoutMs = options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
        this.fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
        this.allowMockFallback = options.allowMockFallback ?? false;
        this.allowInsecureLocalhostDidWeb = options.allowInsecureLocalhostDidWeb ?? false;
    }

    /**
     * Resolve a DID to its Document.
     * Fail-closed: throws DIDResolutionError on any failure.
     */
    async resolve(did: string): Promise<DIDDocument> {
        if (!did || typeof did !== 'string') {
            throw new DIDResolutionError(did, 'Invalid DID string');
        }

        // Check cache
        const cached = this.cache.get(did);
        if (cached && Date.now() < cached.expiresAt) {
            return cached.document;
        }

        // Evict expired entry
        if (cached) {
            this.cache.delete(did);
        }

        let document: DIDDocument;

        if (did.startsWith('did:web:')) {
            document = await this.resolveDidWeb(did);
        } else if (did.startsWith('did:mitch:')) {
            document = await this.resolveDidMitch(did);
        } else if (did.startsWith('did:peer:0z')) {
            // U-02: Inline resolution — no network needed, public key is embedded
            document = await resolveDidPeer0(did);
        } else if (this.allowMockFallback) {
            document = generateMockDIDDocument(did);
        } else {
            throw new DIDResolutionError(did, `Unsupported DID method: ${did.split(':')[1]}`);
        }

        // Validate document
        this.validateDIDDocument(did, document);

        // Cache
        const now = Date.now();
        this.cache.set(did, {
            document,
            resolvedAt: now,
            expiresAt: now + this.cacheTtlMs,
        });

        return document;
    }

    /**
     * Extract a verification key (as jose KeyLike) from a DID Document.
     * 
     * @param doc DID Document
     * @param purpose Which verification relationship to use: 'authentication' | 'assertionMethod'
     *   Falls back to first verificationMethod if purpose-specific list is empty.
     */
    async extractVerificationKey(
        doc: DIDDocument,
        purpose: 'authentication' | 'assertionMethod' = 'assertionMethod'
    ): Promise<KeyLike | Uint8Array> {
        const methods = doc.verificationMethod;
        if (!methods || methods.length === 0) {
            throw new DIDKeyExtractionError(doc.id, 'No verificationMethod entries');
        }

        // Find method matching the purpose relationship
        const purposeRefs = (purpose === 'authentication' ? doc.authentication : doc.assertionMethod) ?? [];
        let method = methods[0]; // default to first

        if (purposeRefs.length > 0) {
            // References can be full URIs or fragment IDs
            const found = methods.find(m =>
                purposeRefs.includes(m.id) ||
                purposeRefs.includes(m.id.split('#').pop()!)
            );
            if (found) method = found;
        }

        if (!method.publicKeyJwk) {
            throw new DIDKeyExtractionError(doc.id, `verificationMethod ${method.id} has no publicKeyJwk`);
        }

        try {
            return await importJWK(method.publicKeyJwk as unknown as JWK);
        } catch (e) {
            throw new DIDKeyExtractionError(
                doc.id,
                `Failed to import JWK from ${method.id}: ${e instanceof Error ? e.message : String(e)}`
            );
        }
    }

    /**
     * Convenience: resolve DID and extract verification key in one call.
     */
    async resolveAndExtractKey(
        did: string,
        purpose: 'authentication' | 'assertionMethod' = 'assertionMethod'
    ): Promise<{ document: DIDDocument; key: KeyLike | Uint8Array }> {
        const document = await this.resolve(did);
        const key = await this.extractVerificationKey(document, purpose);
        return { document, key };
    }

    /**
     * Clear the entire cache.
     */
    clearCache(): void {
        this.cache.clear();
    }

    /**
     * Evict a single DID from cache (e.g., on signature failure to force re-resolve).
     */
    evict(did: string): void {
        this.cache.delete(did);
    }

    /** Visible for testing */
    getCacheEntry(did: string): CachedDIDDocument | undefined {
        return this.cache.get(did);
    }

    // ─── Private ────────────────────────────────────────────────────────────

    private async resolveDidWeb(did: string): Promise<DIDDocument> {
        const url = didWebToUrl(did);
        if (!this.allowInsecureLocalhostDidWeb && isLocalhostDidWeb(did)) {
            throw new DIDResolutionError(did, 'Insecure did:web localhost resolution is blocked');
        }

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), this.fetchTimeoutMs);

            const response = await this.fetchFn(url, { signal: controller.signal });
            clearTimeout(timeout);

            if (!response.ok) {
                throw new DIDResolutionError(did, `HTTP ${response.status} from ${url}`);
            }

            const doc = await response.json();
            return doc as DIDDocument;
        } catch (e) {
            if (e instanceof DIDResolutionError) throw e;
            throw new DIDResolutionError(did, `Fetch failed for ${url}`, e);
        }
    }

    private async resolveDidMitch(did: string): Promise<DIDDocument> {
        const backendUrl = 'http://localhost:3002/did.json';
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), this.fetchTimeoutMs);

            const response = await this.fetchFn(backendUrl, { signal: controller.signal });
            clearTimeout(timeout);

            if (!response.ok) {
                throw new DIDResolutionError(did, `Backend returned HTTP ${response.status}`);
            }

            const doc = await response.json();
            return doc as DIDDocument;
        } catch (e) {
            if (e instanceof DIDResolutionError) throw e;
            throw new DIDResolutionError(did, 'Demo backend unreachable', e);
        }
    }

    private validateDIDDocument(did: string, doc: DIDDocument): void {
        if (!doc || typeof doc !== 'object') {
            throw new DIDResolutionError(did, 'Response is not a valid object');
        }
        if (!doc.id) {
            throw new DIDResolutionError(did, 'DID Document missing "id" field');
        }
        if (!doc['@context'] || !Array.isArray(doc['@context'])) {
            throw new DIDResolutionError(did, 'DID Document missing or invalid "@context"');
        }
    }
}

// ─── URL Conversion ─────────────────────────────────────────────────────────

/**
 * Convert a did:web DID to its resolution URL.
 * 
 * did:web:example.com → https://example.com/.well-known/did.json
 * did:web:example.com:user:alice → https://example.com/user/alice/did.json
 * did:web:localhost%3A3002 → http://localhost:3002/.well-known/did.json [BEST EFFORT: dev-only]
 */
export function didWebToUrl(did: string): string {
    if (!did.startsWith('did:web:')) {
        throw new Error(`Not a did:web DID: ${did}`);
    }

    let domain = did.slice('did:web:'.length);
    // Decode percent-encoded colons (ports)
    domain = decodeURIComponent(domain);

    const parts = domain.split(':');
    const host = parts[0];

    // Detect if second part is a port number
    let hostWithPort = host;
    let pathStart = 1;
    if (parts.length > 1 && /^\d+$/.test(parts[1])) {
        hostWithPort = `${host}:${parts[1]}`;
        pathStart = 2;
    }

    const pathSegments = parts.slice(pathStart);
    const protocol = (host === 'localhost' || host.startsWith('127.0.0.1')) ? 'http' : 'https';

    if (pathSegments.length > 0) {
        return `${protocol}://${hostWithPort}/${pathSegments.join('/')}/did.json`;
    }
    return `${protocol}://${hostWithPort}/.well-known/did.json`;
}


export function isLocalhostDidWeb(did: string): boolean {
    if (!did.startsWith('did:web:')) return false;
    const domain = decodeURIComponent(did.slice('did:web:'.length));
    return domain.startsWith('localhost') || domain.startsWith('127.0.0.1');
}

// ─── Legacy API (backwards compatible) ──────────────────────────────────────

/** Default resolver instance (fail-closed for production parity) */
let _defaultResolver: DIDResolver | null = null;

function getDefaultResolver(): DIDResolver {
    if (!_defaultResolver) {
        _defaultResolver = new DIDResolver({
            allowMockFallback: false,
            allowInsecureLocalhostDidWeb: false,
        });
    }
    return _defaultResolver;
}

/**
 * @deprecated Use `new DIDResolver().resolve(did)` for fail-closed behavior.
 * This legacy function now remains fail-closed (no mock fallback).
 */
export async function resolveDID(did: string): Promise<DIDDocument> {
    return getDefaultResolver().resolve(did);
}

// ─── Mock (Development Only) ────────────────────────────────────────────────

function generateMockDIDDocument(did: string): DIDDocument {
    if (!did.includes('mock') && !did.includes('example') && !did.includes('mitch')) {
        console.error(`🚨 MOCK DID DOCUMENT GENERATED FOR ${did} — NOT FOR PRODUCTION!`);
    }

    return {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        verificationMethod: [{
            id: `${did}#key-1`,
            type: 'JsonWebKey2020',
            controller: did,
            publicKeyJwk: {
                kty: 'RSA',
                n: 'mock-n-for-testing-only-replace-with-real-key-in-prod',
                e: 'AQAB',
                alg: 'RSA-OAEP-256',
            },
        }],
    };
}

/**
 * Detect the WebCrypto algorithm params for a given JWK.
 */
export function detectKeyAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
    switch (jwk.kty) {
        case 'RSA':
            return { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaHashedImportParams;
        case 'EC':
            return { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' } as EcKeyImportParams;
        case 'OKP':
            throw new Error('UNSUPPORTED_KEY_TYPE: OKP (EdDSA) not yet supported');
        default:
            throw new Error(`UNSUPPORTED_KEY_TYPE: ${jwk.kty}`);
    }
}
