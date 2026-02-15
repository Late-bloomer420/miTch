/**
 * @module @mitch/shared-types/predicates
 * 
 * Predicate type definitions for miTch identity infrastructure.
 * 
 * TWO MODELS:
 * 1. DSL Model (canonical): Full predicate AST with expressions, path-based queries
 * 2. Legacy Model: Simple constraint-based queries (for backward compatibility)
 * 
 * @legal GDPR Art. 5.1.c (Data Minimization)
 *        GDPR Art. 25 (Privacy by Design)
 */

// ============================================================================
// DSL MODEL (CANONICAL) - Expressive predicate language
// ============================================================================

/**
 * Supported comparison operators
 */
export type PredicateOp =
    | 'eq'        // Strict equality
    | 'neq'       // Not equal
    | 'gt'        // Greater than
    | 'gte'       // Greater than or equal
    | 'lt'        // Less than
    | 'lte'       // Less than or equal
    | 'in'        // Value in set
    | 'nin'       // Value not in set
    | 'exists';   // Path exists (non-null)

/**
 * Supported value types for type-safe evaluation.
 * 
 * NOTE: 'age_years' is an explicit type for age verification.
 * Path should point to a birthDate (ISO 8601), value is years threshold.
 * This makes the semantic intent clear vs. ambiguous "date" comparisons.
 */
export type PredicateValueType =
    | 'string'
    | 'number'
    | 'boolean'
    | 'date'       // ISO date comparison
    | 'age_years'  // birthDate → compute age in years → compare
    | 'string[]';  // Array of strings (for in/nin)

/**
 * A single predicate clause (atomic assertion)
 */
export interface PredicateClause {
    /** JSONPath-like path into the credential (e.g., "credentialSubject.birthDate") */
    path: string;

    /** Comparison operator */
    op: PredicateOp;

    /** Expected value or threshold */
    value: unknown;

    /** Type hint for safe comparison */
    type: PredicateValueType;
}

/**
 * Compound predicate with logical operators
 */
export interface PredicateExpression {
    /** Logical operator for combining clauses */
    logic: 'and' | 'or';

    /** Child clauses or nested expressions */
    clauses: Array<PredicateClause | PredicateExpression>;
}

/**
 * Top-level predicate definition
 */
export interface Predicate {
    /** Unique identifier for this predicate (for caching/versioning) */
    id: string;

    /** Human-readable description (for consent UI) */
    description: string;

    /** The actual logic */
    expression: PredicateExpression;

    /** Credential types this predicate applies to */
    credentialTypes: string[];
}

// ============================================================================
// PREDICATE REQUEST (From Verifier)
// ============================================================================

/**
 * What the verifier is asking for (DSL model)
 */
export interface PredicateRequest {
    /** Verifier's DID (for binding) */
    verifierDid: string;

    /** Request nonce (replay protection) */
    nonce: string;

    /** Predicates to evaluate (by ID or inline) */
    predicates: Array<string | Predicate>;

    /** Human-readable purpose (for consent UI) */
    purpose: string;

    /** ISO timestamp of request */
    timestamp: string;
}

// ============================================================================
// PREDICATE RESULT (The Answer - NO PII!)
// ============================================================================

/**
 * Privacy-safe error codes
 */
export type PredicateErrorCode =
    | 'MISSING_PATH'
    | 'TYPE_MISMATCH'
    | 'CRITERIA_NOT_MET'
    | 'INVALID_PREDICATE';

/**
 * Evaluation outcome for a single predicate
 */
export interface PredicateEvaluation {
    /** Predicate ID that was evaluated */
    predicateId: string;

    /** Canonical hash of the predicate (for binding) */
    predicateHash: string;

    /** The result */
    result: boolean;

    /** Privacy-safe reason code if failed */
    reasonCode?: PredicateErrorCode;
}

/**
 * The canonical payload that is signed by the wallet.
 * This is the "Decision Proof".
 */
export interface DecisionProofPayload {
    /** UUID for audit chain */
    decisionId: string;

    /** ISO timestamp of evaluation */
    evaluatedAt: string;

    /** Overall success (all predicates passed) */
    allPassed: boolean;

    /** Results for each requested predicate */
    evaluations: PredicateEvaluation[];

    /** Cryptographic binding to the request */
    binding: {
        /** Hash of the original request (verifierDid + nonce + predicates) */
        requestHash: string;

        /** Echo back verifier DID (anti-poaching) */
        verifierDid: string;

        /** Echo back nonce (anti-replay) */
        nonce: string;

        /** Optional: commitment to evidence (hash of minimal required inputs) */
        evidenceCommitment?: string;
    };
}

/**
 * Complete predicate result package (transport object)
 */
export interface PredicateResult {
    /** The actual proof data */
    proof: DecisionProofPayload;

    /** Wallet's signature over canonicalStringify(proof) */
    signature: string;
}

/**
 * Verification result (verifier side)
 */
export interface PredicateVerificationResult {
    valid: boolean;
    errors: string[];
}

// ============================================================================
// LEGACY MODEL (for backward compatibility with constraint style)
// ============================================================================

/**
 * @deprecated Use Predicate DSL instead
 */
export type LegacyPredicateOperator = 'gte' | 'lte' | 'eq' | 'neq' | 'in_set' | 'not_in_set';

/**
 * @deprecated Use Predicate DSL instead
 */
export type LegacyAttributeKey = 'birthDate' | 'residency' | 'professionalLicense' | 'creditScore' | 'membership';

/**
 * @deprecated Use Predicate DSL instead
 */
export interface LegacyPredicateConstraint {
    attribute: LegacyAttributeKey;
    operator: LegacyPredicateOperator;
    value: string | number | string[];
}

/**
 * @deprecated Use PredicateRequest instead
 */
export interface LegacyPredicateRequest {
    verifierDid: string;
    nonce: string;
    purpose: string;
    constraints: LegacyPredicateConstraint[];
}

/**
 * @deprecated Use PredicateResult instead
 */
export interface LegacyDecisionProof {
    success: boolean;
    decisionId: string;
    timestamp: string;
    commitment: {
        requestHash: string;
        verifierDid: string;
        nonce: string;
    };
    error?: 'MISSING_ATTRIBUTE' | 'CRITERIA_NOT_MET' | 'INVALID_REQUEST';
}

// ============================================================================
// CANONICAL SERIALIZATION (pure JSON, no crypto - runtime agnostic)
// ============================================================================

/**
 * Canonicalize a predicate clause for deterministic comparison.
 */
function canonicalizeClause(clause: PredicateClause): string {
    return JSON.stringify({
        op: clause.op,
        path: clause.path,
        type: clause.type,
        value: Array.isArray(clause.value)
            ? [...clause.value].sort()
            : clause.value
    });
}

/**
 * Canonicalize a predicate expression (recursive).
 */
function canonicalizeExpression(expr: PredicateExpression): string {
    const serializedClauses = expr.clauses.map(c => {
        if ('logic' in c) {
            return canonicalizeExpression(c);
        }
        return canonicalizeClause(c);
    });
    serializedClauses.sort();

    return JSON.stringify({
        logic: expr.logic,
        clauses: serializedClauses
    });
}

/**
 * Canonicalize a full predicate for hashing.
 * NOTE: Does not compute hash (no crypto import). Use @mitch/predicates for hashing.
 */
export function canonicalizePredicate(predicate: Predicate): string {
    return JSON.stringify({
        id: predicate.id,
        credentialTypes: [...predicate.credentialTypes].sort(),
        expression: canonicalizeExpression(predicate.expression)
        // Note: description excluded (not part of semantic identity)
    });
}

/**
 * Canonicalize a predicate request for binding.
 * NOTE: Does not compute hash (no crypto import). Use @mitch/predicates for hashing.
 */
export function canonicalizeRequest(request: PredicateRequest): string {
    const predicateReps = request.predicates.map(p => {
        if (typeof p === 'string') {
            return p; // Predicate ID reference
        }
        return canonicalizePredicate(p); // Inline predicate
    });
    predicateReps.sort();

    return JSON.stringify({
        verifierDid: request.verifierDid,
        nonce: request.nonce,
        predicates: predicateReps,
        timestamp: request.timestamp
        // Note: purpose excluded (not part of cryptographic binding)
    });
}

// ============================================================================
// LEGACY ADAPTER: Convert constraints to DSL Predicate
// ============================================================================

/**
 * Map legacy operator to DSL operator
 */
function mapLegacyOp(op: LegacyPredicateOperator): PredicateOp {
    switch (op) {
        case 'gte': return 'gte';
        case 'lte': return 'lte';
        case 'eq': return 'eq';
        case 'neq': return 'neq';
        case 'in_set': return 'in';
        case 'not_in_set': return 'nin';
        default:
            throw new Error(`UNSUPPORTED_LEGACY_OPERATOR: ${op}`);
    }
}

/**
 * Convert legacy constraint to DSL clause
 */
function constraintToClause(c: LegacyPredicateConstraint): PredicateClause {
    const allowedAttributes: LegacyAttributeKey[] = [
        'birthDate',
        'residency',
        'professionalLicense',
        'creditScore',
        'membership'
    ];

    if (!allowedAttributes.includes(c.attribute)) {
        throw new Error(`UNSUPPORTED_LEGACY_ATTRIBUTE: ${c.attribute}`);
    }

    // birthDate uses age_years type for semantic clarity
    const type: PredicateValueType = c.attribute === 'birthDate'
        ? 'age_years'
        : Array.isArray(c.value)
            ? 'string[]'
            : typeof c.value === 'number'
                ? 'number'
                : 'string';

    return {
        path: c.attribute, // Legacy uses flat attribute names
        op: mapLegacyOp(c.operator),
        value: c.value,
        type
    };
}

/**
 * Convert legacy request to DSL request.
 * @deprecated Use PredicateRequest directly
 */
export function legacyToDSL(legacy: LegacyPredicateRequest): PredicateRequest {
    const predicate: Predicate = {
        id: `legacy-${legacy.nonce.slice(0, 8)}`,
        description: legacy.purpose,
        credentialTypes: ['*'], // Legacy didn't specify credential types
        expression: {
            logic: 'and',
            clauses: legacy.constraints.map(constraintToClause)
        }
    };

    return {
        verifierDid: legacy.verifierDid,
        nonce: legacy.nonce,
        purpose: legacy.purpose,
        predicates: [predicate],
        timestamp: new Date().toISOString()
    };
}
