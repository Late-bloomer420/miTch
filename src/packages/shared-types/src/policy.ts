/**
 * @module @mitch/shared-types/policy
 * 
 * Policy Engine Type Definitions
 * 
 * Defines the data structures for policy rules, verifier requests,
 * decision capsules, and evaluation results used throughout the miTch system.
 */

/**
 * Root manifest for all wallet policies.
 * Contains issuer trust lists, matching rules, and global settings.
 */
export interface PolicyManifest {
    version: string;
    trustedIssuers: TrustedIssuer[];
    rules: PolicyRule[];
    globalSettings?: GlobalPolicySettings;
    delegationRules?: DelegationRules;

    /**
     * ADR-ADTECH-004: User-controlled ad preferences.
     * Defines limits, schedule, categories, and quiet periods.
     * Quantized before sending to any verifier — full detail never transmitted.
     */
    adPreferences?: import('./ad-preferences').UserAdPreferences;

    /**
     * ADR-ADTECH-008: Minimum trust score required for ad-tech verifiers.
     * Verifiers below this threshold are auto-denied.
     * Default: 30
     */
    minVerifierTrustScore?: number;

    /**
     * ADR-ADTECH-008: Require domain attestation for all ad-tech verifiers.
     * Default: true
     */
    requireDomainAttestation?: boolean;

    /**
     * S-02: Monotonisch aufsteigender Versionszähler (Integer ≥ 1).
     * Rollback-Schutz: Manifest mit Version < gespeicherter Version wird abgelehnt.
     */
    manifest_version?: number;

    /**
     * S-02: SHA-256 des Manifest-Inhalts (ohne dieses Feld selbst), hex-kodiert.
     * Ermöglicht Tamper-Erkennung beim Laden des Manifests.
     */
    manifest_hash?: string;
}

/**
 * A trusted credential issuer known to the wallet.
 * Credentials from these issuers are considered valid.
 */
export interface TrustedIssuer {
    /** Decentralized Identifier of the issuer */
    did: string;
    /** Human-readable name */
    name: string;
    /** Credential types this issuer is trusted for */
    credentialTypes: string[];
    /** Optional expiration of trust relationship */
    validUntil?: string;
    /** Role of the issuer (standard, HDAB for research access, emergency) */
    issuerRole?: 'standard' | 'hdab' | 'emergency';
}

/**
 * Geographic scope for data access rules.
 * Based on GDPR adequacy framework + EHDS cross-border requirements.
 */
export type GeoScope =
    | 'eu-only'             // Only EU/EEA verifiers (default for Layer 2+)
    | 'eu-plus-adequacy'    // EU + countries with adequacy decision (JP, KR, etc.)
    | 'global';             // No geographic restriction

/**
 * EHDS usage purpose classification.
 * Primary use = direct patient care; secondary use = research, statistics, policy assessment.
 * These are structurally different legal relationships (GDPR/EHDS).
 */
export type UsagePurpose =
    | 'primaryCare'         // Direct treatment — highest priority
    | 'researchSecondary'   // Science — user can globally opt out
    | 'policyAssessment'    // Government effectiveness measurement
    | 'statistics';         // Aggregated, de-identified

/**
 * A single policy rule for matching verifier requests.
 * Rules are evaluated in priority order to determine access.
 */
export interface PolicyRule {
    /** Unique rule identifier */
    id: string;
    /** Glob pattern to match verifier DIDs */
    verifierPattern: string;
    /** Optional context description */
    context?: string;
    /** Claims allowed for disclosure */
    allowedClaims: string[];
    /** Claims allowed ONLY as ZKP/Predicates (never raw disclosure) */
    provenClaims?: string[];
    /** Claims that must never be disclosed */
    deniedClaims?: string[];
    /** Require issuer to be in trustedIssuers list */
    requiresTrustedIssuer?: boolean;
    /** Maximum age of credential in days */
    maxCredentialAgeDays?: number;
    /** Force user consent even if rule matches */
    requiresUserConsent?: boolean;
    /** Require WebAuthn presence proof (biometric) for this rule */
    requiresPresence?: boolean;
    /** Rule evaluation priority (higher = first) */
    priority?: number;
    /** Minimum protection layer required for this verifier (0=WELT, 1=GRUNDVERSORGUNG, 2=VULNERABLE) */
    minimumLayer?: number;
    /** EHDS usage purpose this rule applies to (default: primaryCare) */
    usagePurpose?: UsagePurpose;
    /** EHDS: Verifier must present a valid HDAB permit for this rule */
    requiresHdabPermit?: boolean;
    /** Geographic scope restriction for this rule */
    geoScope?: GeoScope;
    /** EHDS: Allow break-glass emergency access without prior consent */
    allowBreakGlass?: boolean;

    /**
     * S-01: Kryptografischer Verifier-Fingerprint (SHA-256 des Verifier-DID-Dokuments, hex).
     * Wenn gesetzt: Request MUSS einen passenden fingerprint liefern.
     * Bei Mismatch oder fehlendem Fingerprint → PROMPT (niemals auto-ALLOW).
     */
    verifier_fingerprint?: string;

    /**
     * ADR-ADTECH-004/005: Ad-tech specific settings for this rule.
     * Controls nullifier generation, allowed predicate types, and ad preferences.
     */
    adTechSettings?: {
        /** Allow nullifier generation for frequency capping */
        allowNullifier: boolean;
        /** Which predicate types are permitted for ad verification */
        allowedAdTechPredicates?: ('age_threshold' | 'region_match' | 'humanity_proof')[];
        /** Per-rule override of the manifest-level ad preferences */
        adPreferenceOverride?: Partial<import('./ad-preferences').UserAdPreferences>;
        /** IAB category classification for this verifier (informational) */
        verifierCategory?: string;
    };
}

/**
 * Global settings that apply to all policy evaluations.
 */
export interface GlobalPolicySettings {
    /** Default credential freshness requirement (days) */
    defaultFreshnessDays?: number;
    /** Require explicit consent for all disclosures */
    requireConsentForAll?: boolean;
    /** Deny requests from unknown verifiers by default */
    blockUnknownVerifiers?: boolean;
    /** Strict origin + DID binding for verifiers */
    strictVerifierBinding?: boolean;
    /** EHDS: Global opt-out for secondary use (research, statistics) */
    denySecondaryUse?: boolean;
    /** EHDS: Deny secondary use for specific countries (ISO 3166-1 alpha-2) */
    denySecondaryUseCountries?: string[];
    /** Time in minutes before a cached WebAuthn session expires (0 = ask every time) */
    requireConsentTimeoutMinutes?: number;
}

/**
 * A specific data requirement within a (potentially multi-VC) request.
 */
export interface Requirement {
    credentialType: string;
    requestedClaims: string[];
    requestedProvenClaims?: string[]; // Explicit ZKP predicate requests (e.g. "age >= 18")
    issuerTrustRefs?: string[];       // Optional limit to specific issuers
}

// Re-exporting VerifierRequest here if needed, or keeping it generic
export interface VerifierRequest {
    verifierId: string;
    origin?: string;
    purpose?: string;
    /** Anti-replay nonce from verifier */
    nonce?: string;
    /** EHDS usage purpose declared by the verifier */
    usagePurpose?: UsagePurpose;
    /**
     * Support for multiple requirements (Atomic Bundle)
     * If empty/undefined, falls back to legacy single-VC fields below.
     */
    requirements?: Requirement[];

    // Legacy single-VC fields (for backward compatibility)
    requestedClaims?: string[];
    requestedProvenClaims?: string[];

    /** Optional callback URL if different from origin */
    serviceEndpoint?: string;

    /** T-88: Ephemeral Key for SME Kit (Client-Side Encryption) */
    ephemeralResponseKey?: CryptoKey;

    /**
     * S-01: Kryptografischer Fingerprint, den der Verifier von sich selbst präsentiert.
     * (SHA-256 des Verifier-DID-Dokuments oder Public Key, hex).
     * Wird gegen PolicyRule.verifier_fingerprint geprüft.
     */
    verifier_fingerprint?: string;
}

export interface PolicyEvaluationResult {
    verdict: 'ALLOW' | 'DENY' | 'PROMPT';
    reasonCodes: string[];
    selectedCredentials?: string[];
    matchedRule?: string;
    metadata?: {
        evaluatedAt: number;
        policyVersion: string;
        processingTimeMs: number;
    };
    decisionCapsule?: DecisionCapsule;
    denialResolution?: PolicyDenialResolution;
    originalRequest?: VerifierRequest; // For override re-evaluation
}

// --- Policy Denial & Recovery ---

export type PolicyDenialCode =
    | 'UNKNOWN_VERIFIER'
    | 'NO_SUITABLE_CREDENTIAL'
    | 'ATTRIBUTE_BLOCKED'
    | 'LAYER_VIOLATION'
    | 'FRESHNESS_EXPIRED'
    | 'POLICY_MISMATCH'
    | 'CONSENT_REQUIRED'
    | 'UNTRUSTED_ISSUER'
    | 'CLAIM_NOT_ALLOWED'
    | 'CREDENTIAL_EXPIRED'
    | 'NO_MATCHING_RULE'; // Map to engine ReasonCodes

export type ActionType =
    | 'LOAD_CREDENTIAL'
    | 'LEARN_MORE'
    | 'CONTACT_VERIFIER'
    | 'MANUAL_ENTRY'
    | 'OVERRIDE_WITH_CONSENT'
    | 'REPORT_ISSUE';

export interface DenialAction {
    id: string;
    label: string;
    type: ActionType;
    target?: string; // URL, Credential Type, etc.
    requiresConfirm: boolean;
}

export interface PolicyDenialResolution {
    reasonCode: PolicyDenialCode;
    title: string;
    message: string;
    actions: DenialAction[];
    learnMoreUrl?: string;
    severity: 'CRITICAL' | 'HIGH' | 'WARN';
}


// --- Automaton Resistance Types ---

/**
 * The cryptographic "Truth" binding the policy decision.
 * Generalized for T-29 bundle presentations.
 */
export interface DecisionCapsule {
    decision_id: string; // UUID
    verdict: 'ALLOW' | 'DENY' | 'PROMPT';
    request_hash: string; // SHA-256 of VerifierRequest
    policy_hash: string; // SHA-256 of PolicyManifest used
    verifier_did: string;

    /** T-88: Ephemeral Key (JWK) for Zero-Backend sessions */
    ephemeral_key?: JsonWebKey;

    /** Spec 111: Pairwise ephemeral did:peer:0 for this interaction (unlinkability) */
    pairwise_did?: string;
    /** Spec 111: ECDSA signature of decision_id by pairwise key (hex) */
    pairwise_proof?: string;

    /**
     * Per-requirement authorization results
     */
    authorized_requirements: {
        credential_type: string;
        allowed_claims: string[];
        proven_claims: string[];
        selected_credential_id: string;
        issuer_trust_refs: string[];
    }[];

    nonce?: string; // Anti-replay nonce (must match verifier request)
    audience?: string; // Wallet App ID / Audience
    issued_at?: string; // ISO 8601
    risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
    requires_presence: boolean; // If true, Must trigger Biometric/Passkey
    expires_at: string; // ISO 8601
    wallet_attestation?: string; // Signature or TEE proof
    presence_proof?: string; // WebAuthn/Passkey signature over decision_id

    // Legacy fields (deprecated, for backward compatibility)
    allowed_claims?: string[];
    proven_claims?: string[];
    issuer_trust_refs?: string[];
    selected_credential_id?: string;
}

/**
 * Explicit permissions for automated agents acting on behalf of the user.
 */
export interface DelegationRules {
    allowed_agent_dids: string[];
    limits: {
        max_claims_per_request?: number;
        never_allow_raw_pii?: boolean;
        force_presence_on_categories?: string[]; // e.g. ["FINANCE", "HEALTH"]
    };
    audit_level: 'NONE' | 'SUMMARY' | 'ALL';
}

/**
 * Telemetry and signals for detecting automation.
 * Used for risk scoring, not as a hard gate.
 */
export interface InteractionMetadata {
    timestamp: number;
    userAgent: string;
    // Automation Detection Signals
    accessibilityActive?: boolean;
    inputSource?: 'TOUCH' | 'MOUSE' | 'KEYBOARD' | 'UNKNOWN';
    responseTimeMs?: number; // Time from prompt render to action
    /** Whether the user is currently available to interact (false = unconscious/unreachable) */
    userPresent?: boolean;
    proofOfPresence?: {
        type: 'BIOMETRIC' | 'PIN' | 'PASSKEY';
        success: boolean;
        timestamp: number;
    };
}

/**
 * Supported credential encoding formats.
 * 'sd-jwt' = SD-JWT VC (current default), 'mso_mdoc' = ISO 18013-5 mdoc (CBOR/COSE).
 */
export type CredentialFormat = 'sd-jwt' | 'mso_mdoc';

export interface StoredCredentialMetadata {
    id: string;
    issuer: string;
    type: string[];
    issuedAt: string;
    expiresAt?: string;
    claims: string[];
    /** Credential lifecycle status */
    status?: 'active' | 'dispensed' | 'revoked' | 'expired';
    /** Credential encoding format (default: 'sd-jwt') */
    format?: CredentialFormat;
}
