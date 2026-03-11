/**
 * @module @mitch/verifier-sdk/ad-verifier
 *
 * AdTechVerifier — verifier-side ad verification for the miTch Blind Provider flow.
 *
 * Responsibilities:
 * 1. Build AdVerificationRequest objects (with nonce, expiry)
 * 2. Validate AdVerificationResponse (expiry, nonce freshness, scope binding)
 * 3. Enforce frequency caps via NullifierStore
 *
 * Privacy guarantees maintained:
 * - Never stores PII
 * - Nullifiers are scoped per (verifierDid, scopeId) — not shared across campaigns
 * - Budget signals are ephemeral — not stored
 */

import { verifyNullifierScope } from '@mitch/predicates';
import type {
    AdVerificationRequest,
    AdVerificationResponse,
    AdTechPredicate,
} from '@mitch/shared-types';
import type { NullifierStore } from './ad-nullifier-store';

// ---------------------------------------------------------------------------
// Config & result types
// ---------------------------------------------------------------------------

export interface AdTechVerifierConfig {
    /** Verifier's DID — included in nullifier formula to prevent cross-verifier correlation */
    verifierDid: string;
    /** Clock skew tolerance in seconds (default: 90) */
    clockSkewSeconds?: number;
    /** Request TTL in seconds (default: 300) */
    requestTtlSeconds?: number;
    /** Nullifier store for frequency capping (required for cap enforcement) */
    nullifierStore?: NullifierStore;
    /** Used nonces — prevents request replay */
    usedNonces?: Set<string>;
}

export interface CreateAdRequestOptions {
    scopeId: string;
    predicates: AdTechPredicate[];
    category?: { taxonomy: 'IAB-3.0'; primary: string; secondary?: string[] };
    ttlSeconds?: number;
}

export interface AdVerificationResult {
    valid: boolean;
    errors: string[];
    verdict: 'ALLOW' | 'DENY' | 'PROMPT';
    denyReason?: AdVerificationResponse['denyReason'];
    /** Validated nullifier — safe to use for frequency capping */
    nullifier?: string;
    budgetSignal?: AdVerificationResponse['budgetSignal'];
    predicateResults: AdVerificationResponse['predicateResults'];
    verifiedAt: Date;
}

// ---------------------------------------------------------------------------
// AdTechVerifier
// ---------------------------------------------------------------------------

export class AdTechVerifier {
    private readonly clockSkew: number;
    private readonly requestTtl: number;
    private readonly usedNonces: Set<string>;

    constructor(private readonly config: AdTechVerifierConfig) {
        this.clockSkew = (config.clockSkewSeconds ?? 90) * 1000;
        this.requestTtl = config.requestTtlSeconds ?? 300;
        this.usedNonces = config.usedNonces ?? new Set();
    }

    // -----------------------------------------------------------------------
    // Request creation
    // -----------------------------------------------------------------------

    /**
     * Build an AdVerificationRequest to send to the wallet (via publisher).
     */
    createRequest(options: CreateAdRequestOptions): AdVerificationRequest {
        const nonce = this.generateNonce();
        const now = new Date();
        const ttl = options.ttlSeconds ?? this.requestTtl;
        const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();

        return {
            verifierDid: this.config.verifierDid,
            scopeId: options.scopeId,
            predicates: options.predicates,
            category: options.category,
            nonce,
            expiresAt,
        };
    }

    // -----------------------------------------------------------------------
    // Response verification
    // -----------------------------------------------------------------------

    /**
     * Verify a wallet AdVerificationResponse.
     *
     * Checks:
     * 1. Response not expired (validUntil)
     * 2. Nonce not replayed
     * 3. Scope binding valid (if ALLOW + nullifier present)
     * 4. Nullifier bound to this verifier's DID
     *
     * Note: Full wallet signature verification requires wallet DID resolution
     * and is delegated to the calling layer (policy-engine integration, post-MVP).
     */
    verify(response: AdVerificationResponse, requestNonce?: string): AdVerificationResult {
        const now = Date.now();
        const errors: string[] = [];

        // 1. Expiry check
        const validUntil = new Date(response.validUntil).getTime();
        if (now > validUntil + this.clockSkew) {
            errors.push('Response expired');
        }

        // 2. Timestamp not in the future
        const timestamp = new Date(response.timestamp).getTime();
        if (timestamp > now + this.clockSkew) {
            errors.push('Response timestamp is in the future');
        }

        // 3. Nonce replay check (if request nonce provided)
        if (requestNonce) {
            if (this.usedNonces.has(requestNonce)) {
                errors.push(`Nonce replay detected: ${requestNonce}`);
            } else {
                this.usedNonces.add(requestNonce);
            }
        }

        // 4. Scope binding validation (only on ALLOW with nullifier)
        if (response.verdict === 'ALLOW' && response.nullifier) {
            const { value, scopeBinding, boundVerifierDid } = response.nullifier;

            // Nullifier must be bound to THIS verifier
            if (boundVerifierDid !== this.config.verifierDid) {
                errors.push(
                    `Nullifier bound to wrong verifier: expected ${this.config.verifierDid}, got ${boundVerifierDid}`
                );
            }

            // Extract scopeId from response for binding verification
            // The scope binding must be verifiable even without knowing the original scopeId
            // here we verify the binding is self-consistent using the provided verifierDid
            // Full scope binding requires the original request scopeId
            const scopeResult = verifyNullifierScope(
                value,
                this.config.verifierDid,
                this.extractScopeId(response),
                scopeBinding
            );

            if (!scopeResult.valid) {
                errors.push(`Scope binding invalid: ${scopeResult.reason ?? 'unknown'}`);
            }
        }

        const valid = errors.length === 0;
        const nullifier =
            valid && response.verdict === 'ALLOW' && response.nullifier
                ? response.nullifier.value
                : undefined;

        return {
            valid,
            errors,
            verdict: valid ? response.verdict : 'DENY',
            denyReason: response.denyReason,
            nullifier,
            budgetSignal: valid ? response.budgetSignal : undefined,
            predicateResults: response.predicateResults,
            verifiedAt: new Date(),
        };
    }

    // -----------------------------------------------------------------------
    // Frequency cap
    // -----------------------------------------------------------------------

    /**
     * Check and enforce frequency cap for a nullifier.
     * Returns the new impression count, or null if no store is configured.
     */
    async checkFrequencyCap(
        nullifier: string,
        scopeId: string,
        maxImpressions: number
    ): Promise<{ allowed: boolean; impressions: number }> {
        if (!this.config.nullifierStore) {
            // No store — cap not enforced, always allow
            return { allowed: true, impressions: 0 };
        }
        const current = await this.config.nullifierStore.getCount(nullifier, scopeId);
        return { allowed: current < maxImpressions, impressions: current };
    }

    /**
     * Record an impression for a nullifier (call after serving an ad).
     */
    async recordImpression(
        nullifier: string,
        scopeId: string,
        ttlSeconds?: number
    ): Promise<number> {
        if (!this.config.nullifierStore) return 0;
        return this.config.nullifierStore.incrementCount(nullifier, scopeId, ttlSeconds);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private generateNonce(): string {
        const bytes = new Uint8Array(16);
        globalThis.crypto.getRandomValues(bytes);
        // base64url encode without Buffer (works in browser + Node 19+)
        return btoa(String.fromCharCode(...bytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    /**
     * Extract scopeId from the nullifier binding proof context.
     * The scopeId is embedded in the binding proof as the scope component.
     *
     * Note: In production, the original request scopeId should be passed
     * alongside the response for full verification. This is a structural placeholder.
     */
    private extractScopeId(_response: AdVerificationResponse): string {
        // In a complete implementation, the request scopeId would be
        // passed alongside the response or embedded in the binding proof.
        // For MVP, the scope binding check in verify() should be called
        // with the original request's scopeId via verifyWithScope().
        return '';
    }
}

// ---------------------------------------------------------------------------
// Standalone scope-binding verification (preferred for production)
// ---------------------------------------------------------------------------

/**
 * Verify an ad response against its originating request.
 * Preferred over AdTechVerifier.verify() when you have the original request.
 */
export function verifyAdResponse(
    response: AdVerificationResponse,
    request: AdVerificationRequest,
    verifierDid: string,
    clockSkewMs = 90_000
): AdVerificationResult {
    const now = Date.now();
    const errors: string[] = [];

    // Expiry
    if (now > new Date(response.validUntil).getTime() + clockSkewMs) {
        errors.push('Response expired');
    }

    // Future timestamp
    if (new Date(response.timestamp).getTime() > now + clockSkewMs) {
        errors.push('Response timestamp is in the future');
    }

    // Request expiry
    if (now > new Date(request.expiresAt).getTime() + clockSkewMs) {
        errors.push('Request expired');
    }

    // Scope binding (only on ALLOW)
    if (response.verdict === 'ALLOW' && response.nullifier) {
        const { value, scopeBinding, boundVerifierDid } = response.nullifier;

        if (boundVerifierDid !== verifierDid) {
            errors.push(`Nullifier bound to wrong verifier DID`);
        }

        const scopeResult = verifyNullifierScope(value, verifierDid, request.scopeId, scopeBinding);
        if (!scopeResult.valid) {
            errors.push(`Scope binding invalid: ${scopeResult.reason ?? 'unknown'}`);
        }
    }

    const valid = errors.length === 0;
    return {
        valid,
        errors,
        verdict: valid ? response.verdict : 'DENY',
        denyReason: response.denyReason,
        nullifier:
            valid && response.verdict === 'ALLOW' && response.nullifier
                ? response.nullifier.value
                : undefined,
        budgetSignal: valid ? response.budgetSignal : undefined,
        predicateResults: response.predicateResults,
        verifiedAt: new Date(),
    };
}
