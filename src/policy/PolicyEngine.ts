/**
 * PolicyEngine (Layer 2)
 * 
 * CONSTRAINTS:
 * - NEVER touches raw data from vault
 * - Only receives AccessRequest
 * - Outputs ConsentDecision (yes or no)
 * - Rules are hardcoded in Phase 0
 * - No knowledge of what data looks like, only category names
 */

import { AccessRequest } from "../types/AccessRequest";
import { ConsentDecision } from "../types/ConsentDecision";

export class PolicyEngine {
  /**
   * Evaluate if an access request should be allowed
   * 
   * @param request - What is being asked for, and why?
   * @returns Binary decision (allowed or denied)
   * 
   * SECURITY: This engine never sees the actual data.
   * It only knows rules like "age verification is allowed for age_gate purpose".
   */
  public evaluateAccess(request: AccessRequest): ConsentDecision {
    const decision: ConsentDecision = {
      requestId: request.requestId,
      decidedAt: Date.now(),
      allowed: false,
      reason: "Default deny"
    };

    // Phase 0 hardcoded rules (no external configuration)
    if (request.dataCategories.includes("age")) {
      if (request.purpose === "age_gate" || request.purpose === "age_verification") {
        decision.allowed = true;
        decision.reason = "Age verification for age_gate is allowed";
        decision.constraints = {
          validUntil: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
          auditLog: true
        };
        return decision;
      }
    }

    if (request.dataCategories.includes("email")) {
      // Phase 0: email access is always denied
      decision.allowed = false;
      decision.reason = "Email data is not shared in this phase";
      return decision;
    }

    // Unknown category or purpose
    decision.reason = "Request does not match any approved policy";
    return decision;
  }
}
