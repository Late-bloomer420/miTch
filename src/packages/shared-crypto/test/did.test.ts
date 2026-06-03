/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Tests for DID Resolution + Signature Verification
 * 
 * Covers:
 * - did:web URL conversion
 * - DID resolution with caching
 * - Key extraction from DID Documents
 * - Signature verification against resolved keys
 * - Fail-closed behavior (resolution failure, key mismatch, timeout, malformed docs)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import {
    DIDResolver,
    DIDResolutionError,
    DIDKeyExtractionError,
    didWebToUrl,
    resolveDID,
    isLocalhostDidWeb,
} from '../src/did';
import { DIDSignatureVerifier as DIDSigVerifier2 } from '../src/did-verification';

// ─── did:web URL conversion ────────────────────────────────────────────────

describe('didWebToUrl', () => {
    it('converts basic domain', () => {
        expect(didWebToUrl('did:web:example.com')).toBe('https://example.com/.well-known/did.json');
    });

    it('converts domain with path', () => {
        expect(didWebToUrl('did:web:example.com:user:alice')).toBe('https://example.com/user/alice/did.json');
    });

    it('converts localhost with percent-encoded port', () => {
        expect(didWebToUrl('did:web:localhost%3A3002')).toBe('http://localhost:3002/.well-known/did.json');
    });

    it('converts localhost with port and path', () => {
        expect(didWebToUrl('did:web:localhost%3A3002:user:bob')).toBe('http://localhost:3002/user/bob/did.json');
    });

    it('throws for non did:web', () => {
        expect(() => didWebToUrl('did:key:z6Mk...')).toThrow('Not a did:web');
    });
});

// ─── DID Resolution ────────────────────────────────────────────────────────

describe('DIDResolver', () => {
    let resolver: DIDResolver;
    let mockFetch: ReturnType<typeof vi.fn>;

    const validDoc = {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:web:example.com',
        verificationMethod: [{
            id: 'did:web:example.com#key-1',
            type: 'JsonWebKey2020',
            controller: 'did:web:example.com',
            publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' },
        }],
    };

    beforeEach(() => {
        mockFetch = vi.fn();
        resolver = new DIDResolver({
            fetchFn: mockFetch as any,
            cacheTtlMs: 5000,
            fetchTimeoutMs: 2000,
            allowMockFallback: false,
        });
    });

    it('resolves did:web successfully', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => validDoc,
        });

        const doc = await resolver.resolve('did:web:example.com');
        expect(doc.id).toBe('did:web:example.com');
        expect(doc.verificationMethod).toHaveLength(1);
        expect(mockFetch).toHaveBeenCalledOnce();
    });

    it('caches resolved documents', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => validDoc,
        });

        await resolver.resolve('did:web:example.com');
        await resolver.resolve('did:web:example.com');
        expect(mockFetch).toHaveBeenCalledOnce(); // only one fetch
    });

    it('re-resolves after cache expiry', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => validDoc,
        });

        // Use a very short TTL
        resolver = new DIDResolver({
            fetchFn: mockFetch as any,
            cacheTtlMs: 1, // 1ms TTL
            allowMockFallback: false,
        });

        await resolver.resolve('did:web:example.com');
        // Wait for cache to expire
        await new Promise(r => setTimeout(r, 10));
        await resolver.resolve('did:web:example.com');
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('DENY on HTTP error (fail-closed)', async () => {
        mockFetch.mockResolvedValue({ ok: false, status: 404 });

        await expect(resolver.resolve('did:web:example.com'))
            .rejects.toThrow(DIDResolutionError);
    });

    it('DENY on network error (fail-closed)', async () => {
        mockFetch.mockRejectedValue(new Error('Network error'));

        await expect(resolver.resolve('did:web:example.com'))
            .rejects.toThrow(DIDResolutionError);
    });

    it('DENY on malformed DID document (missing id)', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ '@context': ['https://www.w3.org/ns/did/v1'] }),
        });

        await expect(resolver.resolve('did:web:example.com'))
            .rejects.toThrow(/missing "id" field/);
    });

    it('DENY on malformed DID document (missing @context)', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ id: 'did:web:example.com' }),
        });

        await expect(resolver.resolve('did:web:example.com'))
            .rejects.toThrow(/@context/);
    });

    it('DENY on unsupported DID method (no mock fallback)', async () => {
        await expect(resolver.resolve('did:key:z6Mk...'))
            .rejects.toThrow(/Unsupported DID method/);
    });

    it('DENY on timeout (fail-closed)', async () => {
        mockFetch.mockImplementation(() => new Promise((_, reject) => {
            setTimeout(() => reject(new Error('aborted')), 5000);
        }));

        resolver = new DIDResolver({
            fetchFn: mockFetch as any,
            fetchTimeoutMs: 50,
            allowMockFallback: false,
        });

        await expect(resolver.resolve('did:web:slow.example.com'))
            .rejects.toThrow(DIDResolutionError);
    });
});

// ─── Key Extraction ────────────────────────────────────────────────────────

describe('DIDResolver.extractVerificationKey', () => {
    let resolver: DIDResolver;

    beforeEach(() => {
        resolver = new DIDResolver({ allowMockFallback: false });
    });

    it('extracts ES256 key from verificationMethod', async () => {
        const { publicKey } = await generateKeyPair('ES256');
        const jwk = await exportJWK(publicKey);

        const doc = {
            '@context': ['https://www.w3.org/ns/did/v1'] as any,
            id: 'did:web:example.com',
            verificationMethod: [{
                id: 'did:web:example.com#key-1',
                type: 'JsonWebKey2020',
                controller: 'did:web:example.com',
                publicKeyJwk: jwk as any,
            }],
        };

        const key = await resolver.extractVerificationKey(doc);
        expect(key).toBeTruthy();
    });

    it('DENY when no verificationMethod', async () => {
        const doc = {
            '@context': ['https://www.w3.org/ns/did/v1'] as any,
            id: 'did:web:example.com',
            verificationMethod: [],
        };

        await expect(resolver.extractVerificationKey(doc))
            .rejects.toThrow(DIDKeyExtractionError);
    });

    it('DENY when no publicKeyJwk', async () => {
        const doc = {
            '@context': ['https://www.w3.org/ns/did/v1'] as any,
            id: 'did:web:example.com',
            verificationMethod: [{
                id: 'did:web:example.com#key-1',
                type: 'JsonWebKey2020',
                controller: 'did:web:example.com',
            }],
        };

        await expect(resolver.extractVerificationKey(doc))
            .rejects.toThrow(/no publicKeyJwk/);
    });
});

// ─── DID Signature Verification (end-to-end) ───────────────────────────────

describe('DIDSignatureVerifier', () => {
    it('verifies valid JWT signed with DID-resolved key → ALLOW', async () => {
        const { publicKey, privateKey } = await generateKeyPair('ES256');
        const pubJwk = await exportJWK(publicKey);

        const didDoc = {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: 'did:web:example.com',
            verificationMethod: [{
                id: 'did:web:example.com#key-1',
                type: 'JsonWebKey2020',
                controller: 'did:web:example.com',
                publicKeyJwk: pubJwk,
            }],
            assertionMethod: ['did:web:example.com#key-1'],
        };

        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => didDoc,
        });

        const verifier = new DIDSigVerifier2({ fetchFn: mockFetch as any });

        // Sign a JWT with the private key
        const jwt = await new SignJWT({ provenClaims: { 'age >= 18': true } })
            .setProtectedHeader({ alg: 'ES256' })
            .setIssuedAt()
            .sign(privateKey);

        const result = await verifier.verifyPresentation(jwt, 'did:web:example.com');
        expect(result.verified).toBe(true);
        expect(result.payload?.provenClaims).toEqual({ 'age >= 18': true });
    });

    it('DENY when DID resolution fails', async () => {
        const mockFetch = vi.fn().mockRejectedValue(new Error('Network down'));
        const verifier = new DIDSigVerifier2({ fetchFn: mockFetch as any });

        const result = await verifier.verifyPresentation('some.jwt.here', 'did:web:unreachable.com');
        expect(result.verified).toBe(false);
        expect(result.errorCode).toBe('RESOLUTION_FAILED');
    });

    it('DENY on key mismatch (signed with different key)', async () => {
        const { publicKey: resolvedPub } = await generateKeyPair('ES256');
        const { privateKey: differentPriv } = await generateKeyPair('ES256');
        const pubJwk = await exportJWK(resolvedPub);

        const didDoc = {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: 'did:web:example.com',
            verificationMethod: [{
                id: 'did:web:example.com#key-1',
                type: 'JsonWebKey2020',
                controller: 'did:web:example.com',
                publicKeyJwk: pubJwk,
            }],
        };

        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => didDoc,
        });

        const verifier = new DIDSigVerifier2({ fetchFn: mockFetch as any });

        // Sign with a DIFFERENT key than what the DID resolves to
        const jwt = await new SignJWT({ test: true })
            .setProtectedHeader({ alg: 'ES256' })
            .setIssuedAt()
            .sign(differentPriv);

        const result = await verifier.verifyPresentation(jwt, 'did:web:example.com');
        expect(result.verified).toBe(false);
        expect(result.errorCode).toBe('SIGNATURE_INVALID');
    });

    it('DENY on malformed DID document', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ garbage: true }),
        });

        const verifier = new DIDSigVerifier2({ fetchFn: mockFetch as any });

        const result = await verifier.verifyPresentation('some.jwt', 'did:web:bad.com');
        expect(result.verified).toBe(false);
        expect(result.errorCode).toBe('RESOLUTION_FAILED');
    });

    it('DENY on network timeout', async () => {
        const mockFetch = vi.fn().mockImplementation(
            () => new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
        );

        const verifier = new DIDSigVerifier2({
            fetchFn: mockFetch as any,
            fetchTimeoutMs: 50,
        });

        const result = await verifier.verifyPresentation('some.jwt', 'did:web:slow.com');
        expect(result.verified).toBe(false);
        expect(result.errorCode).toBe('RESOLUTION_FAILED');
    });
});


describe('P0 hardening findings', () => {
    it('DENY: did:web localhost is blocked by default', async () => {
        const resolver = new DIDResolver({
            fetchFn: vi.fn() as any,
            allowMockFallback: false,
        });

        await expect(resolver.resolve('did:web:localhost%3A3002'))
            .rejects.toThrow(/Insecure did:web localhost resolution is blocked/);
    });

    it('can explicitly allow localhost did:web only when configured', async () => {
        const didDoc = {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: 'did:web:localhost%3A3002',
            verificationMethod: [{
                id: 'did:web:localhost%3A3002#key-1',
                type: 'JsonWebKey2020',
                controller: 'did:web:localhost%3A3002',
                publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' },
            }],
        };
        const fetchFn = vi.fn().mockResolvedValue({ ok: true, json: async () => didDoc });
        const resolver = new DIDResolver({
            fetchFn: fetchFn as any,
            allowInsecureLocalhostDidWeb: true,
        });

        const result = await resolver.resolve('did:web:localhost%3A3002');
        expect(result.id).toBe('did:web:localhost%3A3002');
    });

    it('DENY: legacy resolveDID no longer allows mock fallback', async () => {
        await expect(resolveDID('did:key:z6MklegacyFallbackAttempt'))
            .rejects.toThrow(/Unsupported DID method/);
    });

    it('detects localhost did:web identifiers', () => {
        expect(isLocalhostDidWeb('did:web:localhost%3A3002')).toBe(true);
        expect(isLocalhostDidWeb('did:web:example.com')).toBe(false);
    });
});
