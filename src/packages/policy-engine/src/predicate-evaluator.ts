import {
    LegacyPredicateRequest,
    LegacyDecisionProof,
    legacyToDSL,
    PredicateErrorCode
} from '@mitch/shared-types';
import { evaluatePredicates, hashRequest } from '@mitch/predicates';

/**
 * T-51: Edge-First Predicate Evaluator
 * 
 * REFACTORED (T-60):
 * This class now acts as a Facade/Adapter over the new @mitch/predicates engine.
 * It maintains backward compatibility with the Legacy Constraint Model while using
 * the robust DSL engine internally.
 */
export class PredicateEvaluator {

    /**
     * Execute logic on raw data WITHOUT exposing it.
     * Evaluates using @mitch/predicates DSL engine.
     * 
     * @param userData - Raw PII from Secure Storage
     * @param request - Legacy constraint-based request
     */
    static async evaluate(
        userData: Record<string, any>,
        request: LegacyPredicateRequest,
        signer: (data: string) => Promise<string> // T-73: Injected Signer (Required)
    ): Promise<LegacyDecisionProof> {

        const dslRequest = legacyToDSL(request);

        // The 'signer' argument is already passed directly to evaluatePredicates.
        // The instruction seems to imply a test call was meant to be added,
        // but it was malformed and placed inside this method.
        // The original code already correctly uses the 'signer' argument.
        const result = await evaluatePredicates(userData, dslRequest, signer);

        let errorReason: 'MISSING_ATTRIBUTE' | 'CRITERIA_NOT_MET' | 'INVALID_REQUEST' | undefined;

        if (!result.proof.allPassed) {
            const firstError = result.proof.evaluations.find(e => !e.result)?.reasonCode;
            if (firstError === 'MISSING_PATH') errorReason = 'MISSING_ATTRIBUTE';
            else if (firstError === 'TYPE_MISMATCH') errorReason = 'INVALID_REQUEST';
            else errorReason = 'CRITERIA_NOT_MET';
        }

        return {
            success: result.proof.allPassed,
            decisionId: result.proof.decisionId,
            timestamp: result.proof.evaluatedAt,
            commitment: {
                requestHash: result.proof.binding.requestHash,
                verifierDid: result.proof.binding.verifierDid,
                nonce: result.proof.binding.nonce
            },
            error: errorReason
        };
    }

    /**
     * Verify the binding of a proof to a request.
     * Adapter for legacy tests.
     */
    static verifyProofBinding(
        proof: LegacyDecisionProof,
        request: LegacyPredicateRequest
    ): { valid: boolean; reason?: string } {
        // Check Metadata
        if (proof.commitment.verifierDid !== request.verifierDid) {
            return { valid: false, reason: `Verifier DID mismatch: expected ${request.verifierDid}, got ${proof.commitment.verifierDid}` };
        }
        if (proof.commitment.nonce !== request.nonce) {
            return { valid: false, reason: `Nonce mismatch: expected ${request.nonce}, got ${proof.commitment.nonce}` };
        }

        // Check Hash
        // We must convert Legacy Request to DSL to match the hash in the proof
        try {
            const dslRequest = legacyToDSL(request);
            dslRequest.timestamp = proof.timestamp;
            const expectedHash = hashRequest(dslRequest); // Sync hash (Node.js)

            if (proof.commitment.requestHash !== expectedHash) {
                return {
                    valid: false,
                    reason: `Request hash mismatch: expected ${expectedHash}, got ${proof.commitment.requestHash}`
                };
            }
        } catch (err: unknown) {
            return { valid: false, reason: `Hashing error: ${err instanceof Error ? err.message : String(err)}` };
        }

        return { valid: true };
    }
}
