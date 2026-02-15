/**
 * @module @mitch/shared-crypto/did
 * 
 * Decentralized Identifier (DID) Resolution Utilities
 * 
 * Implements T-81: Universal DID Resolver
 * Supports:
 * - did:web (Production-Standard, HTTPS)
 * - did:mitch (Demo Backend)
 * - Mock Fallback (Development)
 */

import { DIDDocument } from '@mitch/shared-types';

/**
 * Resolve a DID to its Document.
 * 
 * @param did The DID string to resolve.
 */
export async function resolveDID(did: string): Promise<DIDDocument> {
    // 1. did:web Resolution (Production-Grade)
    // Spec: https://w3c-ccg.github.io/did-method-web/
    if (did.startsWith('did:web:')) {
        let domain = did.replace('did:web:', '');

        // Handle percent-encoded colons (for ports)
        // e.g., did:web:localhost%3A3002 -> localhost:3002
        domain = domain.replace(/%3A/g, ':');

        // Standard did:web path mapping
        // did:web:example.com -> example.com/.well-known/did.json
        // did:web:example.com:user:alice -> example.com/user/alice/did.json
        const parts = domain.split(':');
        const host = parts[0];
        const pathSegments = parts.slice(1);

        const protocol = (host.startsWith('localhost') || host.startsWith('127.0.0.1')) ? 'http' : 'https';

        let url = `${protocol}://${host}/.well-known/did.json`;
        if (pathSegments.length > 0) {
            // If parts were split by colon but one of them was a port number, we might have issues.
            // But did:web spec says colons are path separators. Ports must be percent encoded before the method-specific string.
            // If the user did `did:web:localhost%3A3002`, `domain` is `localhost:3002`.
            // `parts` will be `['localhost', '3002']`. This logic assumes `3002` is a path segment.
            // We need a smarter parser for host:port vs host:path.
            // However, for PoC, if it contains a port-like number, treat it as host part.

            if (domain.includes(':') && !Number.isNaN(parseInt(parts[1]))) {
                // It's likely a port (e.g. localhost:3002)
                const port = parts[1];
                const realPath = parts.slice(2);
                url = `${protocol}://${host}:${port}/.well-known/did.json`;
                if (realPath.length > 0) {
                    url = `${protocol}://${host}:${port}/${realPath.join('/')}/did.json`;
                }
            } else {
                url = `${protocol}://${host}/${pathSegments.join('/')}/did.json`;
            }
        }

        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const doc = await response.json();
            return doc as DIDDocument;
        } catch (e) {
            console.error(`[DID Resolver] Failed to resolve ${did} (${url}):`, e);
            throw new Error(`DID_RESOLUTION_FAILED: ${did}`);
        }
    }

    // 2. did:mitch Resolution (Demo Backend)
    // T-35b: Demo-specific method for local development
    if (did.startsWith('did:mitch:')) {
        // In a real app, this would be a config var. For PoC, hardcoded to port 3002.
        const backendUrl = 'http://localhost:3002/did.json';
        try {
            const response = await fetch(backendUrl);
            if (!response.ok) throw new Error(`Backend offline`);
            const doc = await response.json();
            return doc as DIDDocument;
        } catch (e) {
            console.warn(`[DID Resolver] Demo backend unreachable, using mock for ${did}`);
            // Fallthrough to mock
        }
    }

    // 3. Fallback: Mock (for offline demos / unit tests)
    console.warn(`⚠️ Unsupported DID method or offline: ${did}. Using mock.`);
    return generateMockDIDDocument(did);
}

/**
 * Generate a mock DID Document for testing/offline usage.
 * NEVER USE IN PRODUCTION.
 */
function generateMockDIDDocument(did: string): DIDDocument {
    // This should NEVER happen in production
    if (!did.includes('mock') && !did.includes('example') && !did.includes('mitch')) {
        console.error(`🚨 MOCK DID DOCUMENT GENERATED FOR ${did} - NOT FOR PRODUCTION!`);
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
                alg: 'RSA-OAEP-256'
            }
        }]
    };
}

/**
 * Detect the WebCrypto algorithm params generic for a given JWK.
 */
export function detectKeyAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
    switch (jwk.kty) {
        case 'RSA':
            // Default to RSA-OAEP for encryption keys in this system
            return { name: 'RSA-OAEP', hash: 'SHA-256' } as RsaHashedImportParams;
        case 'EC':
            return { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' } as EcKeyImportParams;
        case 'OKP':
            throw new Error('UNSUPPORTED_KEY_TYPE: OKP (EdDSA) not yet supported');
        default:
            throw new Error(`UNSUPPORTED_KEY_TYPE: ${jwk.kty}`);
    }
}
