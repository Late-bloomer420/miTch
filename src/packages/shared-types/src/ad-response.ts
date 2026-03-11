/**
 * @module @mitch/shared-types/ad-response
 *
 * Request/response types for the Ad-Tech Blind Provider verification flow.
 *
 * Flow:
 *   Verifier → AdVerificationRequest → Wallet
 *   Wallet   → AdVerificationResponse → Verifier
 *
 * Privacy guarantees:
 * - No PII in any response field
 * - Nullifier is unlinkable across scopes (verifier_did in formula)
 * - Budget signal is quantized (see ad-preferences.ts)
 * - Blocked verifiers get POLICY_NO_MATCH — indistinguishable from unknown
 */

import type { AdTechPredicate, AdTechPredicateResult } from './ad-predicates';
import type { QuantizedBudgetSignal } from './ad-preferences';

// ---------------------------------------------------------------------------
// Request (Verifier → Wallet)
// ---------------------------------------------------------------------------

export interface AdVerificationRequest {
    /** Verifier's DID (used in nullifier formula — prevents cross-verifier correlation) */
    verifierDid: string;
    /** Campaign/ad-group scope for nullifier binding */
    scopeId: string;
    /** Predicates to evaluate on user's credentials */
    predicates: AdTechPredicate[];
    /** IAB Content Taxonomy v3.0 category of the ad */
    category?: {
        taxonomy: 'IAB-3.0';
        primary: string;
        secondary?: string[];
    };
    /** Anti-replay nonce (single-use) */
    nonce: string;
    /** Request expiry (ISO 8601) */
    expiresAt: string;
}

// ---------------------------------------------------------------------------
// Response (Wallet → Verifier)
// ---------------------------------------------------------------------------

export interface AdVerificationResponse {
    /** Overall verdict */
    verdict: 'ALLOW' | 'DENY' | 'PROMPT';
    /** Deny reason — POLICY_NO_MATCH for unknown AND blocked verifiers (no leakage) */
    denyReason?: AdDenyReason;
    /** Per-predicate evaluation results (no raw values, only boolean + hash) */
    predicateResults: AdTechPredicateResult[];
    /** Unlinkable nullifier — only present on ALLOW */
    nullifier?: {
        value: string;          // base64url SHA-256
        scopeBinding: string;   // base64url — proves nullifier belongs to this scope
        boundVerifierDid: string;
    };
    /** Quantized budget signal — only present on ALLOW */
    budgetSignal?: QuantizedBudgetSignal;
    /** Cryptographic binding proof linking response to request */
    bindingProof: string;
    /** Wallet signature over the response (base64url) */
    signature: string;
    /** Response generation timestamp (ISO 8601) */
    timestamp: string;
    /** Response validity window (ISO 8601, short TTL ~60s) */
    validUntil: string;
}

// ---------------------------------------------------------------------------
// Deny reasons
// ---------------------------------------------------------------------------

/**
 * All deny reason codes.
 *
 * Critical privacy rule: VERIFIER_BLOCKED must never be exposed externally.
 * Blocked verifiers receive POLICY_NO_MATCH — identical to "no rule exists".
 * This prevents verifiers from knowing they are explicitly blocked.
 */
export type AdDenyReason =
    // Policy
    | 'POLICY_NO_MATCH'          // No matching rule (also used for VERIFIER_BLOCKED — no leakage)
    // Predicates
    | 'PREDICATE_FAILED'         // One or more predicates returned false
    | 'CREDENTIAL_MISSING'       // Required credential not in wallet
    | 'CREDENTIAL_EXPIRED'       // Credential past validity date
    // User preferences
    | 'CATEGORY_DENIED'          // Ad category blocked by user
    | 'SCHEDULE_DENIED'          // Outside user's allowed time window (also covers quiet periods)
    | 'QUIET_PERIOD'             // Internal use only — maps to SCHEDULE_DENIED externally
    | 'BUDGET_EXHAUSTED'         // User's daily/weekly impression limit reached
    // Security
    | 'BINDING_INVALID'          // Request binding validation failed
    | 'REQUEST_EXPIRED';         // Request nonce or expiry invalid
