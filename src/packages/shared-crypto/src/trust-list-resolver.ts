/**
 * EUDI Trust List (TSL) Resolver
 * Handles dynamic lookup and validation of trusted issuers and verifiers.
 */

import { RiskTier } from '@askmi/revocation-statuslist';
import { verifyData } from './signing.js';
import { canonicalStringify } from './hashing.js';

export interface TrustList {
    id: string;
    version: string;
    validUntil: string;
    issuers: string[];   // DIDs of trusted Issuers
    verifiers: string[]; // DIDs of trusted Verifiers
    signature?: string;  // Hex-encoded ECDSA signature
}

export interface TrustCheckResult {
    isTrusted: boolean;
    decision: 'ALLOW' | 'DENY';
    reason?: string;
    checkedAt: number;
    fromCache: boolean;
}

/**
 * `live` requires an anchor key, a signed list and an HTTPS source. `dev` accepts
 * an unsigned list from any URL and exists for local mock services and tests.
 */
export type TrustMode = 'live' | 'dev';

interface TrustCache {
    tsl: TrustList;
    expiresAt: number;
}

export class EUDITrustListResolver {
    private cache: TrustCache | null = null;
    private fetchFn: typeof fetch;
    private readonly cacheTtlMs: number;
    private readonly gracePeriodMsLowRisk: number;
    private tslUrl: string;
    private anchorPublicKey: CryptoKey | null = null;
    private readonly trustMode: TrustMode;

    constructor(options?: { 
        fetchFn?: typeof fetch;
        cacheTtlMs?: number;
        gracePeriodMsLowRisk?: number;
        /** Defaults to ASKMI_TRUST_MODE; anything other than `dev` means `live`. */
        trustMode?: TrustMode;
    }) {
        this.trustMode =
            options?.trustMode ?? (this.readEnv('ASKMI_TRUST_MODE') === 'dev' ? 'dev' : 'live');
        this.fetchFn = options?.fetchFn ?? globalThis.fetch?.bind(globalThis);
        this.cacheTtlMs = options?.cacheTtlMs ?? 24 * 60 * 60 * 1000; // 24 hours
        this.gracePeriodMsLowRisk = options?.gracePeriodMsLowRisk ?? 4 * 60 * 60 * 1000; // 4 hours
        const envUrl = this.readEnv('ASKMI_TSL_URL', 'MITCH_TSL_URL');
        this.tslUrl = envUrl || 'https://trust.askmi.demo/v1/eudi-lotl.json';
    }

    /** First non-empty value among `names`, from Vite's env and then from Node's. */
    private readEnv(...names: string[]): string | undefined {
        // Vite/browser-safe env access
        const importMetaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
        // Node-safe fallback (without crashing browser where `process` is undefined)
        const maybeProcess = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
        for (const env of [importMetaEnv, maybeProcess?.env]) {
            for (const name of names) {
                const value = env?.[name]?.trim();
                if (value) return value;
            }
        }
        return undefined;
    }

    /**
     * Set the TSL source URL.
     */
    setUrl(url: string): void {
        this.tslUrl = url;
        this.clearCache();
    }

    /**
     * Set the trusted anchor public key for TSL signature verification.
     */
    async setAnchorKey(jwk: JsonWebKey): Promise<void> {
        this.anchorPublicKey = await globalThis.crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        );
    }

    /**
     * Check if an Issuer (by DID) is trusted.
     */
    async isIssuerTrusted(did: string, riskTier: RiskTier = 'high'): Promise<TrustCheckResult> {
        return this.checkEntity(did, 'issuer', riskTier);
    }

    /**
     * Check if a Verifier (by DID) is trusted.
     */
    async isVerifierTrusted(did: string, riskTier: RiskTier = 'high'): Promise<TrustCheckResult> {
        return this.checkEntity(did, 'verifier', riskTier);
    }

    private async checkEntity(
        did: string, 
        type: 'issuer' | 'verifier', 
        riskTier: RiskTier
    ): Promise<TrustCheckResult> {
        const now = Date.now();
        let tsl: TrustList | null = null;
        let fromCache = false;

        // Check cache before attempting fetch
        if (this.cache && now < this.cache.expiresAt) {
            tsl = this.cache.tsl;
            fromCache = true;
        }

        if (!tsl) {
            try {
                tsl = await this.getTSL();
            } catch (e) {
                // Fetch failed — handle based on risk tier and cache availability
                // Only low-risk checks may fall back to a stale list, and only inside the grace window.
                if (this.cache && riskTier === 'low' && now < this.cache.expiresAt + this.gracePeriodMsLowRisk) {
                    tsl = this.cache.tsl;
                    fromCache = true;
                } else {
                    return {
                        isTrusted: false,
                        decision: 'DENY',
                        reason: `TRUST_SOURCE_UNAVAILABLE: ${e instanceof Error ? e.message : String(e)}`,
                        checkedAt: now,
                        fromCache: false
                    };
                }
            }
        }

        if (!tsl) {
             return {
                isTrusted: false,
                decision: 'DENY',
                reason: 'TRUST_SOURCE_UNAVAILABLE',
                checkedAt: now,
                fromCache: false
            };
        }

        const list = type === 'issuer' ? tsl.issuers : tsl.verifiers;
        const trusted = list.includes(did);

        return {
            isTrusted: trusted,
            decision: trusted ? 'ALLOW' : 'DENY',
            reason: trusted ? undefined : `ENTITY_NOT_IN_TSL: ${did}`,
            checkedAt: now,
            fromCache
        };
    }

    private async verifyTslSignature(tsl: TrustList): Promise<void> {
        if (!this.anchorPublicKey) {
            const envJwk = this.readEnv('ASKMI_TSL_ANCHOR_JWK');
            if (envJwk) {
                try {
                    await this.setAnchorKey(JSON.parse(envJwk) as JsonWebKey);
                } catch {
                    throw new Error('TSL_ANCHOR_KEY_INVALID: ASKMI_TSL_ANCHOR_JWK is not a usable P-256 public JWK.');
                }
            }
        }
        if (!this.anchorPublicKey) {
            if (this.trustMode !== 'dev') {
                throw new Error('TSL_ANCHOR_KEY_MISSING: no anchor key is configured to verify the trust list.');
            }
            console.warn('[TrustList] ⚠️ Dev trust mode: no anchor key, trust list signature is NOT verified.');
            return;
        }

        if (!tsl.signature) {
            throw new Error('TSL_SIGNATURE_MISSING: The trust list must be signed in production.');
        }

        const { signature, ...data } = tsl;
        const payload = canonicalStringify(data);
        
        const isValid = await verifyData(payload, signature, this.anchorPublicKey);
        if (!isValid) {
            throw new Error('TSL_SIGNATURE_INVALID: The trust list signature verification failed.');
        }
        
        console.log(`[TrustList] ✅ TSL Signature Verified (v${tsl.version})`);
    }

    private async getTSL(): Promise<TrustList> {
        const now = Date.now();
        if (this.cache && now < this.cache.expiresAt) {
            return this.cache.tsl;
        }

        const url = this.tslUrl;
        if (this.trustMode !== 'dev' && !/^https:\/\//i.test(url)) {
            throw new Error('TSL_URL_INSECURE: the trust list must be fetched over HTTPS.');
        }
        const response = await this.fetchFn(url);
        
        if (!response.ok) {
            throw new Error(`TSL fetch failed: HTTP ${response.status}`);
        }

        const tsl = await response.json() as TrustList;

        // E-42: Verify TSL integrity before caching
        await this.verifyTslSignature(tsl);

        this.cache = {
            tsl,
            expiresAt: now + this.cacheTtlMs
        };

        return tsl;
    }

    /** For testing purposes */
    setFetch(fetchFn: typeof fetch): void {
        this.fetchFn = fetchFn;
    }

    clearCache(): void {
        this.cache = null;
    }
}

export const trustListResolver = new EUDITrustListResolver();
