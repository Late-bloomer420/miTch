/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    DIDResolver,
    DIDResolutionError,
    DIDKeyExtractionError,
    resolveDID,
    isLocalhostDidWeb,
    DIDSignatureVerifier,
    didWebToUrl
} from '../src/index';
import { generateKeyPair, exportKeyToJWK } from '../src/index';
import { SignJWT } from 'jose';

describe('did:web normalization', () => {
    it('converts basic domain', () => {
        expect(didWebToUrl('did:web:example.com'))
            .toBe('https://example.com/.well-known/did.json');
    });

    it('converts domain with path', () => {
        expect(didWebToUrl('did:web:example.com:user:alice'))
            .toBe('https://example.com/user/alice/did.json');
    });

    it('converts localhost with percent-encoded port', () => {
        expect(didWebToUrl('did:web:localhost%3A3002'))
            .toBe('http://localhost:3002/.well-known/did.json');
    });

    it('converts localhost with port and path', () => {
        expect(didWebToUrl('did:web:localhost%3A3002:api'))
            .toBe('http://localhost:3002/api/did.json');
    });

    it('throws for non did:web', () => {
        expect(() => didWebToUrl('did:key:z6Mk...'))
            .toThrow(/Not a did:web DID/);
    });
});

describe('DIDResolver', { timeout: 30_000 }, () => {
    let mockFetch: any;
    let resolver: DIDResolver;

    beforeEach(() => {
        mockFetch = vi.fn();
        resolver = new DIDResolver({
            fetchFn: mockFetch as any,
            allowMockFallback: false,
        });
    });

    it('resolves did:web successfully', async () => {
        const didDoc = {
            '@context': ['https://www.w3.org/ns/did/v1'] as any,
            id: 'did:web:example.com',
            verificationMethod: [],
        };

        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => didDoc,
        });

        const result = await resolver.resolve('did:web:example.com');
        expect(result.id).toBe('did:web:example.com');
    });

    it('caches resolved documents', async () => {
        const didDoc = {
            '@context': ['https://www.w3.org/ns/did/v1'] as any,
            id: 'did:web:cached.com',
        };
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => didDoc,
        });

        await resolver.resolve('did:web:cached.com');
        await resolver.resolve('did:web:cached.com');

        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('re-resolves after cache expiry', async () => {
        const didDoc = {
            '@context': ['https://www.w3.org/ns/did/v1'] as any,
            id: 'did:web:expired.com',
        };
        resolver = new DIDResolver({
            fetchFn: mockFetch as any,
            cacheTtlMs: 0
        });
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => didDoc,
        });

        await resolver.resolve('did:web:expired.com');
        await resolver.resolve('did:web:expired.com');

        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('DENY on HTTP error (fail-closed)', async () => {
        mockFetch.mockResolvedValue({ ok: false, status: 404 });
        await expect(resolver.resolve('did:web:missing.com'))
            .rejects.toThrow(DIDResolutionError);
    });

    it('DENY on network error (fail-closed)', async () => {
        mockFetch.mockRejectedValue(new Error('connection reset'));
        await expect(resolver.resolve('did:web:reset.com'))
            .rejects.toThrow(DIDResolutionError);
    });

    it('DENY on malformed DID document (missing id)', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ '@context': ['https://www.w3.org/ns/did/v1'] }),
        });
        await expect(resolver.resolve('did:web:bad.com'))
            .rejects.toThrow(/missing "id" field/);
    });

    it('DENY on malformed DID document (missing @context)', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            json: async () => ({ id: 'did:web:no-context.com' }),
        });
        await expect(resolver.resolve('did:web:no-context.com'))
            .rejects.toThrow(/missing or invalid "@context"/);
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

describe('DIDResolver.extractVerificationKey', () => {
    let resolver: DIDResolver;

    beforeEach(() => {
        resolver = new DIDResolver({ allowMockFallback: false });
    });

    it('extracts ES256 key from verificationMethod', async () => {
        const { publicKey } = await generateKeyPair();
        const jwk = await exportKeyToJWK(publicKey);

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
            .rejects.toThrow(/has no publicKeyJwk/);
    });
});

describe('DIDSignatureVerifier', { timeout: 30_000 }, () => {
    it('verifies valid JWT signed with DID-resolved key → ALLOW', async () => {
        const { publicKey, privateKey } = await generateKeyPair();
        const pubJwk = await exportKeyToJWK(publicKey);

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

        const verifier = new DIDSignatureVerifier({ fetchFn: mockFetch as any });

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
        const verifier = new DIDSignatureVerifier({ fetchFn: mockFetch as any });

        const result = await verifier.verifyPresentation('some.jwt.here', 'did:web:unreachable.com');
        expect(result.verified).toBe(false);
        expect(result.errorCode).toBe('RESOLUTION_FAILED');
    });

    it('DENY on malformed DID document', async () => {
        const mockFetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ garbage: true }),
        });

        const verifier = new DIDSignatureVerifier({ fetchFn: mockFetch as any });

        const result = await verifier.verifyPresentation('some.jwt', 'did:web:bad.com');
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

    it('detects localhost did:web identifiers', () => {
        expect(isLocalhostDidWeb('did:web:localhost%3A3002')).toBe(true);
        expect(isLocalhostDidWeb('did:web:example.com')).toBe(false);
    });
});
