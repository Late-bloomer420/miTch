import { describe, it, expect } from 'vitest';
import { PredicateEvaluator } from '../src/predicate-evaluator';
import {
    LegacyPredicateRequest as PredicateRequest, // Alias for refactoring
    LegacyDecisionProof as DecisionProof
} from '@mitch/shared-types';

/**
 * T-51 Unit Tests: Predicate Evaluator
 * 
 * REFACTORED (T-60):
 * Tests the Adapter/Facade which delegates to @mitch/predicates.
 */

describe('PredicateEvaluator (Adapter)', () => {

    const mockUserData = {
        birthDate: '1995-06-15',
        residency: 'DE',
        professionalLicense: 'B',
        creditScore: 720,
        membership: 'premium'
    };

    const createMockRequest = (overrides?: Partial<PredicateRequest>): PredicateRequest => ({
        verifierDid: 'did:web:shop.example.com',
        nonce: 'unique-nonce-12345',
        purpose: 'Age verification for purchase',
        constraints: [
            { attribute: 'birthDate', operator: 'gte', value: 18 }
        ],
        ...overrides
    } as PredicateRequest);

    describe('evaluate()', () => {

        it('returns success=true when user meets age requirement', async () => {
            const request = createMockRequest();
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );

            expect(proof.success).toBe(true);
            expect(proof.error).toBeUndefined();
            expect(proof.commitment.verifierDid).toBe(request.verifierDid);
            expect(proof.commitment.nonce).toBe(request.nonce);
        });

        it('returns success=false when user does not meet age requirement', async () => {
            const request = createMockRequest({
                constraints: [
                    { attribute: 'birthDate', operator: 'gte', value: 40 }
                ]
            });
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );

            expect(proof.success).toBe(false);
            expect(proof.error).toBe('CRITERIA_NOT_MET');
        });

        it('returns error for missing attribute', async () => {
            const request = createMockRequest({
                constraints: [
                    { attribute: 'creditScore', operator: 'gte', value: 600 }
                ]
            });
            // Partial user data simulating missing field
            const incompleteUserData = { birthDate: '1995-06-15' };

            const proof = await PredicateEvaluator.evaluate(
                incompleteUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );

            expect(proof.success).toBe(false);
            expect(proof.error).toBe('MISSING_ATTRIBUTE');
        });

        // CRITICAL: PII Non-Disclosure Test
        it('NEVER includes raw PII in the returned proof', async () => {
            const request = createMockRequest();
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );
            const proofString = JSON.stringify(proof);

            expect(proofString).not.toContain('1995-06-15');
            expect(proofString).not.toContain('720');
            expect(proofString).not.toContain('premium');
            expect(proof).toHaveProperty('success');
            expect(proof).toHaveProperty('decisionId');
            expect(proof).toHaveProperty('commitment');
        });
    });

    describe('residency checks', () => {
        it('passes eq operator for matching country', async () => {
            const request = createMockRequest({
                constraints: [
                    { attribute: 'residency', operator: 'eq', value: 'DE' }
                ]
            });
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );
            expect(proof.success).toBe(true);
        });

        it('fails eq operator for non-matching country', async () => {
            const request = createMockRequest({
                constraints: [
                    { attribute: 'residency', operator: 'eq', value: 'US' }
                ]
            });
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );
            expect(proof.success).toBe(false);
        });
    });

    describe('verifyProofBinding()', () => {
        it('returns valid for matching proof and request', async () => {
            const request = createMockRequest();
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );

            const result = PredicateEvaluator.verifyProofBinding(proof, request);
            expect(result.valid).toBe(true);
        });

        it('detects verifier DID mismatch', async () => {
            const request = createMockRequest();
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );

            const differentRequest = createMockRequest({
                verifierDid: 'did:web:attacker.com'
            });

            const result = PredicateEvaluator.verifyProofBinding(proof, differentRequest);

            expect(result.valid).toBe(false);
            expect(result.reason).toContain('Verifier DID mismatch');
        });

        it('detects request hash mismatch (tampered request)', async () => {
            const request = createMockRequest();
            const proof = await PredicateEvaluator.evaluate(
                mockUserData,
                request,
                async (d) => `sig_test_${d.length}`
            );

            const tamperedRequest = createMockRequest({
                constraints: [
                    { attribute: 'birthDate', operator: 'gte', value: 21 }
                ]
            });

            const result = PredicateEvaluator.verifyProofBinding(proof, tamperedRequest);

            expect(result.valid).toBe(false);
            // The logic correctly re-hashes the request and finds a mismatch
            expect(result.reason).toContain('Request hash mismatch');
        });
    });
});
