export * from './engine';
export * from './predicate-evaluator';
export type {
    PolicyManifest,
    PolicyRule,
    TrustedIssuer,
    PolicyEvaluationResult,
    VerifierRequest,
    GlobalPolicySettings,
    // New DSL Types (T-50 Canonical)
    PredicateRequest,
    PredicateResult,
    // Legacy Types (T-60 Adapter Layer)
    LegacyDecisionProof as DecisionProof,
    LegacyPredicateOperator as PredicateOperator,
    LegacyPredicateConstraint as PredicateConstraint,
    LegacyAttributeKey as AttributeKey
} from '@mitch/shared-types';

export * from './policy-validator';
