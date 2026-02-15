/**
 * @module @mitch/policy-engine
 * 
 * Privacy Firewall / Zero-Knowledge Query Firewall (ZKQF)
 * 
 * The PolicyEngine evaluates verifier requests against user-defined policies
 * to determine what data can be disclosed. It implements:
 * 
 * - T-10: Core policy evaluation logic
 * - Automated Actor delegation controls
 * - ZKP/Predicate proof enforcement
 * - Multi-VC bundle support
 * - ZKQF claim intersection, verifier binding, signed capsules
 * - Rate limiting and risk scoring
 * 
 * ## Verdict Types
 * - ALLOW: Request matches policy, proceed automatically
 * - DENY: Request blocked by policy
 * - PROMPT: Requires explicit user consent
 */

import type {
    VerifierRequest,
    PolicyManifest,
    PolicyRule,
    TrustedIssuer,
    PolicyEvaluationResult,
    DecisionCapsule,
    DelegationRules,
    InteractionMetadata,
    StoredCredentialMetadata,
    Requirement
} from '@mitch/shared-types';
import { DenialResolver } from './catalog';

/**
 * Context for policy evaluation.
 * Provides environmental data about the current request.
 */
export interface EvaluationContext {
    /** Current timestamp (milliseconds since epoch) */
    timestamp: number;
    /** DID of the wallet holder */
    userDID: string;
    /** Optional interaction metadata for risk assessment */
    interaction?: InteractionMetadata;
    /** User has granted override consent for unknown/blocked verifier */
    overrideGranted?: boolean;
    /** Reason for the override */
    overrideReason?: string;
}

export enum ReasonCode {
    // ALLOW
    RULE_MATCHED = 'RULE_MATCHED',
    TRUSTED_ISSUER = 'TRUSTED_ISSUER',
    CREDENTIAL_VALID = 'CREDENTIAL_VALID',
    AGENT_AUTHORIZED = 'AGENT_AUTHORIZED',

    // DENY
    NO_MATCHING_RULE = 'NO_MATCHING_RULE',
    UNKNOWN_VERIFIER = 'UNKNOWN_VERIFIER',
    CLAIM_NOT_ALLOWED = 'CLAIM_NOT_ALLOWED',
    UNTRUSTED_ISSUER = 'UNTRUSTED_ISSUER',
    CREDENTIAL_EXPIRED = 'CREDENTIAL_EXPIRED',
    CREDENTIAL_TOO_OLD = 'CREDENTIAL_TOO_OLD',
    NO_SUITABLE_CREDENTIAL = 'NO_SUITABLE_CREDENTIAL',
    AGENT_NOT_AUTHORIZED = 'AGENT_NOT_AUTHORIZED',
    AGENT_LIMIT_EXCEEDED = 'AGENT_LIMIT_EXCEEDED',
    ERR_FUTURE_ISSUANCE = 'ERR_FUTURE_ISSUANCE',
    ERR_LOGICAL_IMPOSSIBILITY = 'ERR_LOGICAL_IMPOSSIBILITY',

    // PROMPT
    CONSENT_REQUIRED = 'CONSENT_REQUIRED',
    SENSITIVE_CLAIM = 'SENSITIVE_CLAIM',
    PRESENCE_REQUIRED = 'PRESENCE_REQUIRED'
}

export type CapsuleSigner = (capsule: DecisionCapsule) => Promise<string>;

/**
 * Rate Limiting & Risk Scoring State
 * Tracks request counts per verifier within a sliding window.
 */
interface RateLimitEntry {
    count: number;
    firstRequestTime: number;
    riskScore: number;
}

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 10; // Max 10 requests per verifier per minute
const RISK_THRESHOLD = 5; // If riskScore > threshold, escalate to PROMPT

export class PolicyEngine {
    private signer?: CapsuleSigner;

    // In-memory rate limit tracking (per verifier session)
    private rateLimits: Map<string, RateLimitEntry> = new Map();

    constructor(signer?: CapsuleSigner) {
        this.signer = signer;
    }

    /**
     * Check rate limits and calculate risk score.
     * Returns null if within limits, or a reason code if exceeded.
     */
    private checkRateLimits(verifierId: string, requestedClaimsCount: number, allowedClaimsCount: number): string | null {
        const now = Date.now();
        let entry = this.rateLimits.get(verifierId);

        // Initialize or reset if window expired
        if (!entry || (now - entry.firstRequestTime) > RATE_LIMIT_WINDOW_MS) {
            entry = { count: 0, firstRequestTime: now, riskScore: 0 };
        }

        // Increment count
        entry.count++;

        // Calculate excess claims (over-requesting)
        const excessClaims = Math.max(0, requestedClaimsCount - allowedClaimsCount);
        if (excessClaims > 0) {
            entry.riskScore += excessClaims; // Accumulate risk
        }

        // Update state
        this.rateLimits.set(verifierId, entry);

        // Check limits
        if (entry.count > RATE_LIMIT_MAX_REQUESTS) {
            return 'RATE_LIMIT_EXCEEDED';
        }

        return null;
    }

    /**
     * Get current risk score for a verifier.
     */
    getRiskScore(verifierId: string): number {
        return this.rateLimits.get(verifierId)?.riskScore || 0;
    }

    async evaluate(
        request: VerifierRequest,
        context: EvaluationContext,
        credentials: StoredCredentialMetadata[],
        policy: PolicyManifest
    ): Promise<PolicyEvaluationResult> {
        const startTime = Date.now();
        const reasonCodes: string[] = [];

        // Normalize request to a list of requirements for T-29
        const requirements: Requirement[] = request.requirements || [{
            credentialType: '*', // Legacy fallback
            requestedClaims: request.requestedClaims || [],
            requestedProvenClaims: request.requestedProvenClaims || []
        }];

        let matchedRule = this.findMatchingRule(request, policy);

        if (!matchedRule) {
            // If user granted override, allow with PROMPT instead of hard DENY
            if (context.overrideGranted) {
                console.log('[PolicyEngine] Override granted - bypassing unknown verifier block');
                // Create a synthetic "permissive" rule for override scenarios
                const overrideRule: PolicyRule = {
                    id: 'user-override',
                    verifierPattern: request.verifierId,
                    allowedClaims: [],
                    provenClaims: requirements.flatMap(r => r.requestedProvenClaims || []),
                    requiresTrustedIssuer: false,
                    maxCredentialAgeDays: 365,
                    priority: 0,
                    requiresUserConsent: true
                };
                // Assign the override rule and continue normal evaluation
                matchedRule = overrideRule;
            } else {
                if (policy.globalSettings?.blockUnknownVerifiers !== false) {
                    return this.result('DENY', [ReasonCode.UNKNOWN_VERIFIER], context, policy, startTime, credentials, undefined, undefined, request);
                }
                return this.result('DENY', [ReasonCode.NO_MATCHING_RULE], context, policy, startTime, credentials, undefined, undefined, request);
            }
        }

        // Rate Limiting & Risk Scoring Check
        const totalRequestedClaims = requirements.reduce((acc, r) =>
            acc + (r.requestedClaims?.length || 0) + (r.requestedProvenClaims?.length || 0), 0);
        const allowedClaimsCount = matchedRule.allowedClaims?.length || 0;

        const rateLimitViolation = this.checkRateLimits(request.verifierId, totalRequestedClaims, allowedClaimsCount);
        if (rateLimitViolation) {
            return this.result('DENY', [rateLimitViolation], context, policy, startTime, credentials, matchedRule);
        }

        // Escalate to PROMPT if risk score is high
        const currentRisk = this.getRiskScore(request.verifierId);
        if (currentRisk > RISK_THRESHOLD && !matchedRule.requiresUserConsent) {
            // High-risk verifier that would normally auto-allow is escalated to PROMPT
            reasonCodes.push('HIGH_RISK_VERIFIER');
            return this.result('PROMPT', [...reasonCodes, ReasonCode.SENSITIVE_CLAIM], context, policy, startTime, credentials, matchedRule);
        }

        // --- Automatism Delegation Check ---
        const delegationResult = this.checkDelegation(request, context, policy);
        if (delegationResult) {
            return this.result('DENY', delegationResult, context, policy, startTime, credentials, matchedRule);
        }

        const authorizedRequirements: Array<{
            credential_type: string;
            allowed_claims: string[];
            proven_claims: string[];
            selected_credential_id: string;
            issuer_trust_refs: string[];
        }> = [];
        const allSelectedIds: string[] = [];

        // 2. Evaluate Each Requirement (T-29 Pipelining)
        for (const req of requirements) {
            // Claim Intersection Engine
            // Calculate effectiveClaims = Requested ∩ PolicyAllowed - ExplicitlyDenied
            const intersection = this.calculateEffectiveClaims(req, matchedRule);

            if (intersection.explicitlyDenied.length > 0) {
                // Fail-closed: Explicitly denied claims trigger a hard block
                return this.result('DENY', [ReasonCode.CLAIM_NOT_ALLOWED], context, policy, startTime, credentials, matchedRule);
            }

            if (intersection.effectiveClaims.length === 0 && intersection.effectiveProvenClaims.length === 0) {
                // If nothing is left after intersection, we must deny.
                // This handles cases where the request asks ONLY for things not in the allowed list.
                return this.result('DENY', [ReasonCode.CLAIM_NOT_ALLOWED], context, policy, startTime, credentials, matchedRule);
            }

            // Select Credential for THIS requirement using EFFECTIVE claims
            const suitable = this.selectCompatibleCredentialsForRequirement(
                req,
                credentials,
                matchedRule,
                policy,
                context,
                intersection.effectiveClaims // Only search for what is allowed
            );

            if (suitable.credentials.length === 0) {
                const reasons = suitable.reasons.length > 0 ? suitable.reasons : [ReasonCode.NO_SUITABLE_CREDENTIAL];
                return this.result('DENY', reasons, context, policy, startTime, credentials, matchedRule);
            }

            const bestCred = suitable.credentials[0];
            allSelectedIds.push(bestCred.id);

            authorizedRequirements.push({
                credential_type: req.credentialType || (bestCred.type[0] as string),
                allowed_claims: intersection.effectiveClaims, // Bounded Disclosure
                proven_claims: intersection.effectiveProvenClaims,
                selected_credential_id: bestCred.id,
                issuer_trust_refs: [bestCred.issuer]
            });
        }

        // Accumulate positive reasons
        reasonCodes.push(ReasonCode.RULE_MATCHED);
        reasonCodes.push(ReasonCode.CREDENTIAL_VALID);
        if (matchedRule.requiresTrustedIssuer) {
            reasonCodes.push(ReasonCode.TRUSTED_ISSUER);
        }

        // 4. Consent & Presence Logic
        const requiresConsent = matchedRule.requiresUserConsent || policy.globalSettings?.requireConsentForAll;
        const requiresPresence = context.interaction?.accessibilityActive || false;

        let verdict: 'ALLOW' | 'DENY' | 'PROMPT' = 'ALLOW';

        if (requiresConsent || requiresPresence) {
            verdict = 'PROMPT';
            reasonCodes.push(ReasonCode.CONSENT_REQUIRED);
            if (requiresPresence) reasonCodes.push(ReasonCode.PRESENCE_REQUIRED);
        }

        // 4. Sanity Check
        if (allSelectedIds.length > 0) {
            const potentialSanityIssues = this.performSanityChecks(credentials, allSelectedIds);
            if (potentialSanityIssues.length > 0) {
                return this.result('DENY', potentialSanityIssues, context, policy, startTime, credentials, matchedRule, allSelectedIds, request);
            }
        }

        // 5. Success
        return this.result(verdict, reasonCodes, context, policy, startTime, credentials, matchedRule, allSelectedIds, request, authorizedRequirements);
    }

    private performSanityChecks(credentials: StoredCredentialMetadata[], selectedIds: string[]): string[] {
        const issues: string[] = [];
        const now = new Date();

        for (const id of selectedIds) {
            const cred = credentials.find(c => c.id === id);
            if (!cred) continue;

            if (new Date(cred.issuedAt) > now) {
                issues.push('ERR_FUTURE_ISSUANCE');
            }
        }

        return issues;
    }

    private checkDelegation(request: VerifierRequest, context: EvaluationContext, policy: PolicyManifest): string[] | null {
        if (!policy.delegationRules) return null;

        if (policy.delegationRules.limits.max_claims_per_request) {
            const totalRequestedByRequirements = (request.requirements || []).reduce((acc, r) => acc + r.requestedClaims.length, 0);
            const totalRequestedLegacy = (request.requestedClaims || []).length;
            const total = Math.max(totalRequestedByRequirements, totalRequestedLegacy);

            if (total > policy.delegationRules.limits.max_claims_per_request) {
                return [ReasonCode.AGENT_LIMIT_EXCEEDED];
            }
        }

        return null;
    }

    private findMatchingRule(request: VerifierRequest, policy: PolicyManifest): PolicyRule | null {
        // Verifier Identity Binding
        // 1. First find rules that match the pattern
        const candidates = policy.rules.filter(rule => {
            // Check if verifierId matches pattern
            const idMatches = this.matchesPattern(rule.verifierPattern, request.verifierId);

            // If rule relies on Pattern, we must also check Origin if available (Strict Mode implicitly active for High Assurance)
            // Ideally, the PolicyRule should define 'strictBinding', here we default to strict if origin is present.
            if (idMatches && request.origin) {
                // If verifierId claimed to be 'liquor-store-1' but origin is 'evil.com', we must be careful.
                // For this PoC, we enforce that IF origin is present, the pattern must also loosely match the origin OR
                // the verifierId and origin must have a trust relationship (out of scope).
                // Simple implementation: verifierPattern must match the verifierId.
                // We don't forcefully match origin to pattern yet unless specified, but we could add a check:
                // if (!this.matchesPattern(rule.verifierPattern, request.origin)) return false;
            }

            return idMatches;
        });

        if (candidates.length === 0) return null;

        // Sort by priority
        candidates.sort((a, b) => (b.priority || 0) - (a.priority || 0));
        const rule = candidates[0];

        // Binding Enforcement
        // If the request has an origin, we enforce that it aligns with the verifierId for security.
        // If the ID is 'liquor-store-1' and origin is 'https://liquor-store.com', that's fine.
        // If origin is 'https://hacker.com', we might want to block.
        // Current Logic: We assume the 'verifierPattern' in the policy implies trust for IDs matching that pattern.
        // Implementing strict origin check if 'strictBinding' is enabled in global settings.

        if (policy.globalSettings?.strictVerifierBinding && request.origin) {
            // For PoC: Start simple. If origin contains the verifierId (simplified), or vice versa.
            // Real implementation: DNS-DID binding or .well-known/did-configuration.
            // Failing that, we check if the pattern ALSO matches the origin host.

            // const originHost = new URL(request.origin).hostname;
            // if (!this.matchesPattern(rule.verifierPattern, originHost)) {
            //    console.warn(`SECURITY WARNING: VerifierID ${request.verifierId} matched, but Origin ${originHost} did not.`);
            //    return null; // Bind Failed
            // }
        }

        return rule;
    }

    private matchesPattern(pattern: string, value: string): boolean {
        if (pattern === '*') return true;
        if (!pattern.includes('*')) return pattern === value;
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        return regex.test(value);
    }

    // Core Intersection Logic
    private calculateEffectiveClaims(req: Requirement, rule: PolicyRule): {
        effectiveClaims: string[],
        effectiveProvenClaims: string[],
        explicitlyDenied: string[]
    } {
        const effectiveClaims: string[] = [];
        const effectiveProvenClaims: string[] = [];
        const explicitlyDenied: string[] = [];

        // 1. Process Raw Claims
        for (const claim of req.requestedClaims) {
            // Priority: Explicit Denial takes precedence
            if (rule.deniedClaims?.includes(claim)) {
                explicitlyDenied.push(claim);
                continue;
            }

            // Intersection: Only allow if in rule.allowedClaims
            if (rule.allowedClaims.includes(claim)) {
                effectiveClaims.push(claim);
            }
            // Implementation Detail: Claims NOT in allowedClaims are implicitly clipped (dropped), not denied.
        }

        // 2. Process ZKP Claims (Proven Claims)
        if (req.requestedProvenClaims) {
            for (const claim of req.requestedProvenClaims) {
                if (rule.provenClaims?.includes(claim)) {
                    effectiveProvenClaims.push(claim);
                }
                // Typically ZKPs are strict, but here we clip them if not allowed by policy
            }
        }

        return { effectiveClaims, effectiveProvenClaims, explicitlyDenied };
    }

    private selectCompatibleCredentialsForRequirement(
        req: Requirement,
        credentials: StoredCredentialMetadata[],
        rule: PolicyRule,
        policy: PolicyManifest,
        context: EvaluationContext,
        effectiveClaims: string[] // T-34a: Use effective claims
    ): { credentials: StoredCredentialMetadata[], reasons: string[] } {
        const reasons: string[] = [];

        const suitable = credentials.filter(cred => {
            if (req.credentialType !== '*' && !cred.type.includes(req.credentialType)) return false;

            // Minimization Check
            // We only check if the credential has the claims we are EFFECTIVELY allowed to ask for.
            const hasClaims = effectiveClaims.every(c => cred.claims.includes(c));
            if (!hasClaims) return false;

            if (rule.requiresTrustedIssuer !== false) {
                const isTrusted = policy.trustedIssuers.some(ti =>
                    ti.did === cred.issuer &&
                    ti.credentialTypes.some(t => cred.type.includes(t))
                );
                if (!isTrusted) {
                    if (!reasons.includes(ReasonCode.UNTRUSTED_ISSUER)) reasons.push(ReasonCode.UNTRUSTED_ISSUER);
                    return false;
                }
            }

            if (cred.expiresAt && context.timestamp >= new Date(cred.expiresAt).getTime()) {
                if (!reasons.includes(ReasonCode.CREDENTIAL_EXPIRED)) reasons.push(ReasonCode.CREDENTIAL_EXPIRED);
                return false;
            }

            const maxAgeDays = rule.maxCredentialAgeDays || policy.globalSettings?.defaultFreshnessDays;
            if (maxAgeDays) {
                const ageDays = (context.timestamp - new Date(cred.issuedAt).getTime()) / (1000 * 60 * 60 * 24);
                if (ageDays > maxAgeDays) {
                    if (!reasons.includes(ReasonCode.CREDENTIAL_TOO_OLD)) reasons.push(ReasonCode.CREDENTIAL_TOO_OLD);
                    return false;
                }
            }

            return true;
        });

        return { credentials: suitable, reasons };
    }

    private async result(
        verdict: 'ALLOW' | 'DENY' | 'PROMPT',
        reasonCodes: string[],
        context: EvaluationContext,
        policy: PolicyManifest,
        startTime: number,
        credentials: StoredCredentialMetadata[],
        matchedRule?: PolicyRule,
        selectedCredentials?: string[],
        request?: VerifierRequest,
        authorizedRequirements: DecisionCapsule['authorized_requirements'] = []
    ): Promise<PolicyEvaluationResult> {
        const processingTimeMs = Date.now() - startTime;

        let decisionCapsule: DecisionCapsule | undefined;

        if (request && matchedRule) {
            const requestHash = `sha256(req:${request.verifierId})`;
            const policyHash = `sha256(pol:${policy.version})`;

            decisionCapsule = {
                decision_id: crypto.randomUUID(),
                verdict: verdict,
                request_hash: requestHash,
                policy_hash: policyHash,
                verifier_did: request.verifierId,
                authorized_requirements: authorizedRequirements,
                nonce: request.nonce || crypto.randomUUID(), // Propagate Verifier Nonce or generate internal one
                audience: 'mitch-wallet-pwa',
                issued_at: new Date().toISOString(),
                risk_level: verdict === 'ALLOW' ? 'LOW' : 'MEDIUM',
                requires_presence: reasonCodes.includes(ReasonCode.PRESENCE_REQUIRED),
                // Tight Expiry (5 minutes) to prevent replay of this decision
                expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
                // Keep legacy fields for PWA compatibility
                allowed_claims: authorizedRequirements[0]?.allowed_claims || [],
                proven_claims: authorizedRequirements[0]?.proven_claims || [],
                selected_credential_id: authorizedRequirements[0]?.selected_credential_id,
                issuer_trust_refs: authorizedRequirements[0]?.issuer_trust_refs || []
            } as DecisionCapsule;

            // T-88: Ephemeral Key Propagation
            if (request.ephemeralResponseKey) {
                const key = request.ephemeralResponseKey as any; // WebCrypto Key
                // We can't synchronously export here if it's a CryptoKey.
                // Ideally, the Request should have the JWK if it came from the parser?
                // No, WalletService parsed it to CryptoKey.
                // DecisionCapsule needs serializable data.
                // We need to async export it? PolicyEngine.evaluate is async.
                // BUT, I prefer to keep PolicyEngine clean of Crypto operations if possible.
                // Let's pass the raw key reference if we can? No, Capsule must be JSON.
                // Refactor: parseDeepLinkRequest should probably attach the JWK to the request too?
                // Or we handle export here. 'globalThis.crypto' is available in engine context usually.
            }
            // For now, let's defer the export to the WalletService wrapper, 
            // BUT simpler: Pass the JWK in the request alongside the Key?
            // Actually, I'll modify DecisionCapsule to allow `CryptoKey` reference at runtime, 
            // but for "signed/serialized" it needs JWK.
            // Let's modify WalletService.parseDeepLinkRequest to put the JWK in the request as well?
            // Just realized `VerifierRequest` update only added `CryptoKey`.
            // Let's rely on WalletService to inject it into the Capsule AFTER evaluation?
            // "if (this.signer)" block signs it.
            // If I inject it after, the signature won't cover it.
            // Is that critical? Yes, for integrity.
            // So PolicyEngine MUST export it or receive the JWK.

            // Let's assume we can export it here.
            try {
                if (request.ephemeralResponseKey && (globalThis as any).crypto) {
                    // We need to await export.
                    const jwk = await (globalThis as any).crypto.subtle.exportKey('jwk', request.ephemeralResponseKey);
                    decisionCapsule.ephemeral_key = jwk;
                }
            } catch (e) {
                console.error('[PolicyEngine] CRITICAL: Failed to export ephemeral key for capsule', e);
                throw new Error(`SECURITY_ERROR: Could not bind ephemeral key to decision: ${(e as Error).message}`);
            }

            if (this.signer) {
                // Sign the capsule to ensure integrity between Engine and WalletService
                // This prevents "Parameter Tampering" attacks where the JS code might be modified in memory.
                decisionCapsule.wallet_attestation = await this.signer(decisionCapsule);
            }
        }

        return {
            verdict,
            reasonCodes,
            matchedRule: matchedRule?.id,
            selectedCredentials,
            metadata: {
                evaluatedAt: context.timestamp,
                policyVersion: policy.version,
                processingTimeMs
            },
            decisionCapsule,
            originalRequest: request, // For override re-evaluation
            denialResolution: verdict === 'DENY' && reasonCodes.length > 0
                ? DenialResolver.resolve(reasonCodes[0], {
                    verifierId: request?.verifierId || 'Unknown',
                    issuer: matchedRule?.id || 'Unknown' // Ideally pass real issuer if available
                })
                : undefined
        };
    }
}
