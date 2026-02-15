/**
 * @mitch/predicates
 * 
 * Predicate subsystem for miTch identity infrastructure.
 * Enables "Structural Non-Existence" by evaluating predicates on-device
 * and returning only cryptographically bound boolean results.
 */

// Types
export type {
    PredicateOp,
    PredicateValueType,
    PredicateClause,
    PredicateExpression,
    Predicate,
    PredicateRequest
} from './canonical';

export type {
    PredicateErrorCode,
    PredicateEvaluation,
    PredicateResult,
    PredicateVerificationResult
} from './types';

// Canonical hashing
export {
    canonicalizePredicate,
    canonicalizeRequest,
    hashPredicate,
    hashRequest,
    sha256,
    hashPredicateAsync,
    hashRequestAsync,
    sha256Async
} from './canonical';

// Wallet-side evaluation
export {
    evaluatePredicates,
    CommonPredicates
} from './evaluate';

// Verifier-side validation
export {
    verifyPredicateResult,
    extractAndVerifyPredicates,
    buildAllowedPredicateSet
} from './verify';
