import { 
    VerifierRequest, 
    PolicyEvaluationResult, 
    PolicyManifest, 
    StoredCredentialMetadata
} from '@askmi/shared-types';
import { EvaluationContext } from '@mitch/policy-engine';

/**
 * Interface for policy evaluation and disclosure authorization.
 * Extracted from WalletService for Phase 2.2 decomposition.
 */
export interface IPolicyEvaluator {
    /**
     * Evaluate a verifier request against the local policy.
     */
    evaluate(
        request: VerifierRequest, 
        context: EvaluationContext, 
        credentials: StoredCredentialMetadata[], 
        policy: PolicyManifest
    ): Promise<PolicyEvaluationResult>;

    /**
     * Get the active policy manifest.
     */
    getPolicy(): PolicyManifest;

    /**
     * Update the active policy.
     */
    savePolicy(policy: PolicyManifest): void;
}
