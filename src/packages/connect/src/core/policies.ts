/**
 * ADOPT-1.1 policy registry. The first code slice registers exactly one
 * policy. Applications choose a registered policy id; they never provide
 * claim lists. Additional policies require a later policy-pack gate.
 */

import type {
  AskMIConnectPolicy,
  AskMIConnectPolicyId,
  AskMIConnectProvenance,
  AskMIConnectResult,
} from './types';

import type { CreateSessionInput } from './types';

export const ageLiquorStorePolicy: AskMIConnectPolicy = Object.freeze({
  id: 'age-liquor-store-v1',
  version: 1,
  purpose: 'Liquor purchase age eligibility',
  profile: 'sd-jwt-vc-age-v1',
  requestedClaims: Object.freeze(['age'] as const),
  requiredClaims: Object.freeze(['age'] as const),
  resultClaim: 'eligible',
} as const);

const POLICIES: ReadonlyMap<AskMIConnectPolicyId, AskMIConnectPolicy> = new Map([
  [ageLiquorStorePolicy.id, ageLiquorStorePolicy],
]);

export function lookupPolicy(policyId: unknown): AskMIConnectPolicy | null {
  if (typeof policyId !== 'string') return null;
  return POLICIES.get(policyId as AskMIConnectPolicyId) ?? null;
}

/**
 * Evaluate the application result from the disclosed claims. The result is
 * a separate application decision (backlog #170): cryptographic validity of
 * a signed `age` never implies eligibility.
 * Eligibility for the liquor-store policy: age is a finite number >= 18.
 */
export function evaluatePolicyResult(
  policy: AskMIConnectPolicy,
  disclosedClaims: Record<string, unknown>
): AskMIConnectResult {
  const age = disclosedClaims['age'];
  const eligible = typeof age === 'number' && Number.isFinite(age) && age >= 18;
  return { eligible };
}

/** Claim names shared vs. withheld, derived from the policy and the claims
 * actually present after successful verification. Names only, no values. */
export function provenanceFor(
  policy: AskMIConnectPolicy,
  disclosedClaims: Record<string, unknown>,
  correlationId: string
): AskMIConnectProvenance {
  const shared = policy.requestedClaims.filter((claim) => claim in disclosedClaims);
  const withheld = policy.requestedClaims.filter((claim) => !(claim in disclosedClaims));
  return {
    policyId: policy.id,
    policyVersion: policy.version,
    credentialProfile: policy.profile,
    claimsShared: shared,
    claimsWithheld: withheld,
    correlationId,
  };
}

/** Only the policy id is honored from create input; everything else is ignored. */
export function sanitizeCreateInput(input: CreateSessionInput): CreateSessionInput {
  return { policyId: input.policyId, returnUrl: input.returnUrl };
}
