import { VerificationRequestV0 } from "../types/api";
import { DecisionResult } from "../types/decision";
import { PolicyManifestV0 } from "../types/policy";

export function evaluatePolicy(request: VerificationRequestV0, policy: PolicyManifestV0): DecisionResult {
  if (policy.version !== "v0") {
    return { decision: "DENY", decisionCode: "DENY_POLICY_UNSUPPORTED_VERSION", claimsSatisfied: [] };
  }

  if (!policy.purposes.includes(request.purpose)) {
    return { decision: "DENY", decisionCode: "DENY_POLICY_PURPOSE_MISMATCH", claimsSatisfied: [] };
  }

  for (const claim of request.claims) {
    const allowed = policy.predicates.find((p) => p.name === claim.name && p.allowed);
    if (!allowed) {
      return { decision: "DENY", decisionCode: "DENY_POLICY_UNKNOWN_PREDICATE", claimsSatisfied: [] };
    }
  }

  return {
    decision: "ALLOW",
    decisionCode: "ALLOW_MINIMAL_PROOF_VALID",
    claimsSatisfied: request.claims.map((c) => ({ name: c.name, value: c.value })),
  };
}
