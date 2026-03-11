/**
 * @module @mitch/shared-types/ad-predicates
 *
 * Ad-Tech predicate types for privacy-preserving ad verification.
 *
 * These predicates evaluate boolean/categorical claims about the user
 * without exposing raw PII to verifiers.
 * Supported: age threshold, region match, humanity proof.
 */

// ---------------------------------------------------------------------------
// Individual predicate types
// ---------------------------------------------------------------------------

/**
 * Prove age >= minAge without revealing date of birth.
 */
export interface AgeThresholdPredicate {
    type: 'age_threshold';
    /** Minimum age in years (e.g. 18 for adult content) */
    minAge: number;
    /** Optional reference date for calculation (ISO 8601; defaults to today) */
    referenceDate?: string;
}

/**
 * Prove the user is in one of the allowed regions.
 * granularity controls how precise the region claim is.
 */
export interface RegionMatchPredicate {
    type: 'region_match';
    /** List of allowed ISO country/state codes */
    allowedRegions: string[];
    /** How precise the region match is */
    granularity: 'country' | 'state' | 'postal_prefix';
}

/**
 * Prove the user is a real human (anti-bot).
 * minTrustLevel controls how strongly this is asserted.
 */
export interface HumanityProofPredicate {
    type: 'humanity_proof';
    minTrustLevel: 'self_asserted' | 'verified' | 'government_issued';
}

// ---------------------------------------------------------------------------
// Union type
// ---------------------------------------------------------------------------

export type AdTechPredicate =
    | AgeThresholdPredicate
    | RegionMatchPredicate
    | HumanityProofPredicate;

// ---------------------------------------------------------------------------
// Evaluation result (returned by wallet, no raw values)
// ---------------------------------------------------------------------------

export interface AdTechPredicateResult {
    predicateType: AdTechPredicate['type'];
    /** SHA-256 hash of the predicate parameters — links result to request without replay */
    predicateHash: string;
    /** Boolean result — true = predicate satisfied */
    result: boolean;
    /** Credential type used to evaluate (e.g. "AgeCredential") */
    credentialType: string;
    /** DID of the issuer who issued the credential */
    issuerDid: string;
}
