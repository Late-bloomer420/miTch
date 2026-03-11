/**
 * @module @mitch/shared-types/verifier-trust
 *
 * Verifier attestation and reputation types.
 *
 * Trust model (ADR-ADTECH-008):
 * 1. Domain Attestation: DNS-DNSSEC → did:web (proves domain ownership)
 * 2. LEI Binding: optional Legal Entity Identifier (increases trust)
 * 3. Category Declaration: verifier commits to IAB categories up-front
 * 4. Reputation Score: volume bonus + violation rate penalty
 * 5. Deny List: denyListed verifiers score 0, wallets reject their requests
 */

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

/**
 * Verifier attestation for trust establishment.
 * Verifier publishes this and wallets cache + validate it.
 */
export interface VerifierAttestation {
    /** Verifier's decentralized identifier (e.g. did:web:ads.example.com) */
    did: string;

    /**
     * Domain ownership proof via DNS-DNSSEC.
     * TXT record at _mitch-verifier.<domain> contains DID signature.
     */
    domainProof: {
        domain: string;
        txtRecord: string;
        dnssecValidated: boolean;
        validatedAt: string; // ISO 8601
    };

    /**
     * Legal Entity Identifier binding (optional).
     * Provides stronger real-world accountability than DNS alone.
     */
    leiBinding?: {
        lei: string;
        registrationAuthority: string;
        validUntil: string; // ISO 8601
    };

    /**
     * Declared IAB Content Taxonomy v3.0 categories.
     * Verifier commits to these; violations trigger reputation slashing.
     */
    declaredCategories: {
        taxonomy: 'IAB-3.0';
        primary: string[];
        /** Categories this verifier will NEVER serve (binding commitment) */
        forbidden: string[];
    };

    /** Attestation validity period */
    validFrom: string;   // ISO 8601
    validUntil: string;  // ISO 8601

    /** Signature over attestation fields by verifier's DID key (base64url) */
    signature: string;
}

// ---------------------------------------------------------------------------
// Reputation
// ---------------------------------------------------------------------------

/**
 * Reputation state for a verifier.
 * Maintained by a reputation registry (decentralised or federated — open question).
 */
export interface VerifierReputation {
    did: string;
    successfulTransactions: number;
    /** Total violation reports received (unconfirmed) */
    violationReports: number;
    /** Confirmed violations after review */
    confirmedViolations: number;
    /** Current trust score (0–100). See calculateTrustScore(). */
    trustScore: number;
    /** If true, wallets MUST reject requests from this verifier */
    denyListed: boolean;
    denyListReason?: string;
    denyListedAt?: string; // ISO 8601
}

// ---------------------------------------------------------------------------
// Trust score calculation
// ---------------------------------------------------------------------------

/**
 * Calculate verifier trust score (0–100).
 *
 * Factors:
 * - Base: 50
 * - Volume bonus: log10(transactions) × 5, capped at +20
 * - Violation penalty: (confirmedViolations / transactions) × 500, capped at -50
 * - Deny-listed: always 0
 */
export function calculateTrustScore(rep: VerifierReputation): number {
    if (rep.denyListed) return 0;

    const base = 50;
    const volumeBonus = Math.min(20, Math.log10(rep.successfulTransactions + 1) * 5);
    const violationRate = rep.confirmedViolations / (rep.successfulTransactions + 1);
    const violationPenalty = Math.min(50, violationRate * 500);

    return Math.max(0, Math.min(100, base + volumeBonus - violationPenalty));
}
