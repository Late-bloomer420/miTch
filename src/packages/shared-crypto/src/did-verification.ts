/**
 * @module @mitch/shared-crypto/did-verification
 * 
 * Combined DID Resolution + Signature Verification
 * 
 * Resolves a presenter's DID, extracts the verification key,
 * and verifies the presentation signature against it.
 * 
 * SECURITY: Fail-closed — any failure = DENY
 */

import { jwtVerify } from 'jose';
import type { JWTVerifyResult } from 'jose';
import { DIDResolver, DIDResolverOptions, DIDResolutionError, DIDKeyExtractionError } from './did.js';

export interface DIDVerificationResult {
    verified: boolean;
    /** The DID that was resolved */
    did: string;
    /** JWT payload if verification succeeded */
    payload?: Record<string, unknown>;
    /** Error message if verification failed */
    error?: string;
    /** Error code for programmatic handling */
    errorCode?: 'RESOLUTION_FAILED' | 'KEY_EXTRACTION_FAILED' | 'SIGNATURE_INVALID' | 'UNKNOWN';
}

export class DIDSignatureVerifier {
    private resolver: DIDResolver;

    constructor(options?: DIDResolverOptions) {
        // Production: never allow mock fallback
        this.resolver = new DIDResolver({ ...options, allowMockFallback: false });
    }

    /**
     * Verify a JWT presentation signature against the presenter's DID-resolved key.
     * 
     * Fail-closed: returns { verified: false } on ANY failure.
     * Never throws — all errors are captured in the result.
     */
    async verifyPresentation(
        jwt: string,
        presenterDid: string,
        options?: { purpose?: 'authentication' | 'assertionMethod' }
    ): Promise<DIDVerificationResult> {
        const purpose = options?.purpose ?? 'assertionMethod';

        try {
            // 1. Resolve DID → DID Document
            const { key } = await this.resolver.resolveAndExtractKey(presenterDid, purpose);

            // 2. Verify JWT signature against resolved key
            const result: JWTVerifyResult = await jwtVerify(jwt, key);

            return {
                verified: true,
                did: presenterDid,
                payload: result.payload as Record<string, unknown>,
            };
        } catch (e) {
            if (e instanceof DIDResolutionError) {
                return {
                    verified: false,
                    did: presenterDid,
                    error: e.message,
                    errorCode: 'RESOLUTION_FAILED',
                };
            }
            if (e instanceof DIDKeyExtractionError) {
                return {
                    verified: false,
                    did: presenterDid,
                    error: e.message,
                    errorCode: 'KEY_EXTRACTION_FAILED',
                };
            }
            // jose verification failures, key mismatches, etc.
            return {
                verified: false,
                did: presenterDid,
                error: e instanceof Error ? e.message : String(e),
                errorCode: 'SIGNATURE_INVALID',
            };
        }
    }

    /**
     * Force cache eviction for a DID (e.g., after a failed verification to re-resolve).
     */
    evict(did: string): void {
        this.resolver.evict(did);
    }

    clearCache(): void {
        this.resolver.clearCache();
    }
}
