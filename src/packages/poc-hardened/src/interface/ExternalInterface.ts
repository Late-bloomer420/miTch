/**
 * ExternalInterface (Layer 4)
 * 
 * CONSTRAINTS:
 * - ONLY receives and sends proofs
 * - Stateless - no data storage
 * - Orchestrates the layer chain: Request → Policy → Proof → Response
 * - Never touches raw data
 */

import { AccessRequest } from "../types/AccessRequest";
import { Proof } from "../types/Proof";
import { PolicyEngine } from "../policy/PolicyEngine";
import { ProofEngine } from "../proof/ProofEngine";
import { PersonalDataVault } from "../vault/PersonalDataVault";

export class ExternalInterface {
  constructor(
    private policyEngine: PolicyEngine,
    private proofEngine: ProofEngine
  ) {}

  /**
   * Handle external access request (public API)
   * 
   * Flow:
   * 1. External system sends AccessRequest
   * 2. Policy engine decides: allowed?
   * 3. Proof engine generates abstract proof (no data)
   * 4. Return proof to external system
   * 
   * @param request - What is being asked for?
   * @returns Proof (abstract, no raw data exposed)
   */
  public handleAccessRequest(request: AccessRequest): Proof[] {
    const proofs: Proof[] = [];

    // Step 1: Policy evaluation
    const decision = this.policyEngine.evaluateAccess(request);

    // Step 2: For each requested category, generate proof
    for (const category of request.dataCategories) {
      const proof = this.proofEngine.generateProof(decision, request.userId, category);
      proofs.push(proof);
    }

    return proofs;
  }
}

/**
 * Factory to instantiate the complete system (Phase 0)
 */
export function createSystem(): {
  interface: ExternalInterface;
  vault: PersonalDataVault;
} {
  const vault = new PersonalDataVault();
  const policyEngine = new PolicyEngine();
  const proofEngine = new ProofEngine(vault);
  const externalInterface = new ExternalInterface(policyEngine, proofEngine);

  return {
    interface: externalInterface,
    vault: vault
  };
}
