/**
 * DID-based key resolver for the PoC hardened server.
 * 
 * Bridges the ResolveKey interface with @mitch/shared-crypto DIDResolver.
 * When keyId looks like a DID (starts with "did:"), resolves via DID Document.
 * Otherwise falls back to the provided fallback resolver.
 * 
 * Fail-closed: DID resolution failure = { status: "unavailable" }
 */

import { ResolveKey, ResolvedKey } from './keyResolver';
import { DIDResolver, DIDResolverOptions } from '@mitch/shared-crypto';

export function createDIDKeyResolver(
    fallback: ResolveKey,
    options?: DIDResolverOptions
): ResolveKey {
    const resolver = new DIDResolver({ ...options, allowMockFallback: false });

    return async (keyId?: string): Promise<ResolvedKey> => {
        if (!keyId) return { status: 'missing' };

        // Only handle DID-based key IDs
        if (!keyId.startsWith('did:')) {
            return fallback(keyId);
        }

        try {
            // keyId might be "did:web:example.com#key-1" or just "did:web:example.com"
            const [did] = keyId.split('#');
            const doc = await resolver.resolve(did);

            // Find the specific verification method if fragment is provided
            const fragment = keyId.includes('#') ? keyId : undefined;
            const methods = doc.verificationMethod ?? [];

            const method = fragment
                ? methods.find(m => m.id === keyId || m.id === fragment)
                : methods[0];

            if (!method?.publicKeyJwk) {
                return { status: 'missing' };
            }

            // Convert JWK to PEM for compatibility with existing PoC
            // For now, return the JWK stringified as "PEM" — the PoC verify logic
            // will need to handle JWK format. This is a bridge.
            return {
                status: 'active',
                publicKeyPem: JSON.stringify(method.publicKeyJwk),
            };
        } catch {
            // Fail-closed: any resolution error = unavailable
            return { status: 'unavailable' };
        }
    };
}
