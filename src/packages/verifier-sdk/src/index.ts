
export * from './types';
export * from './VerifierSDK';

// Claim/Predicate Contract — ingress validator + re-exported contract for external verifiers
export { validateClaimRequest } from './claim-validation';
export type { ClaimRequestValidation } from './claim-validation';
export {
    CLAIM_CONTRACT_VERSION,
    CLAIM_CONTRACT_SCHEMA_V1,
    CANONICAL_CLAIMS,
    resolveClaim,
    getFormatBinding,
    UnknownClaimError,
} from '@askmi/shared-types';
export type { CanonicalClaim, CredentialFormatId, ClaimFormatBinding } from '@askmi/shared-types';

// Ad-Tech Blind Provider
export type { NullifierStore } from './ad-nullifier-store';
export { InMemoryNullifierStore, RedisNullifierStore } from './ad-nullifier-store';
export type { AdTechVerifierConfig, CreateAdRequestOptions, AdVerificationResult } from './ad-verifier';
export { AdTechVerifier, verifyAdResponse } from './ad-verifier';
