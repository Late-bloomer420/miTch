import { describe, it, expect, beforeEach } from 'vitest';
import {
    evaluatePredicates,
    verifyPredicateResult,
    buildAllowedPredicateSet,
    CommonPredicates,
    hashPredicateAsync,
    hashRequestAsync,
    PredicateRequest
} from '../src/index';

/**
 * E2E Integration Tests: Wallet → Verifier
 * 
 * Proves:
 * 1. Raw PII never leaves the wallet
 * 2. Proof is cryptographically bound to the request
 * 3. Verifier can detect tampering, replay, poaching
 */

// Mock Wallet Sign Function
async function mockWalletSign(data: string): Promise<string> {
    return `sig_${Buffer.from(data).toString('base64').slice(0, 32)}`;
}

// Mock Verifier Verify Function
async function mockVerifierVerify(data: string, signature: string): Promise<boolean> {
    const expected = `sig_${Buffer.from(data).toString('base64').slice(0, 32)}`;
    return signature === expected;
}

describe('Predicate E2E: Wallet → Verifier', () => {

    // Sample credential (from wallet's secure storage)
    const mockCredential = {
        credentialSubject: {
            id: 'did:key:user-alice',
            birthDate: '1995-06-15',  // ~30 years old
            residency: 'DE',
            name: 'Alice Smith',      // Should NOT leak
            ssn: '123-45-6789'        // Should DEFINITELY NOT leak
        }
    };

    // ========================================================================
    // WALLET SIDE: Evaluate Predicates (Local, Device-Only)
    // ========================================================================

    describe('Wallet: evaluatePredicates()', () => {

        it('evaluates age predicate and returns result without PII', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:shop.example.com',
                nonce: 'nonce-shop-123',
                purpose: 'Age verification for liquor purchase',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            const result = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            // Result should be TRUE (user is ~30, request is >= 18)
            expect(result.proof.allPassed).toBe(true);
            expect(result.proof.evaluations[0].result).toBe(true);

            // CRITICAL: Serialize entire result and check for PII
            const resultString = JSON.stringify(result);
            expect(resultString).not.toContain('1995-06-15');   // birthDate
            expect(resultString).not.toContain('Alice Smith');  // name
            expect(resultString).not.toContain('123-45-6789'); // ssn
            expect(resultString).not.toContain('DE');          // residency (could leak location)

            // Result should have binding
            expect(result.proof.binding.verifierDid).toBe(request.verifierDid);
            expect(result.proof.binding.nonce).toBe(request.nonce);
            expect(result.proof.binding.requestHash).toBeDefined();

            // Result should be signed
            expect(result.signature).toBeDefined();
        });

        it('fails age predicate when user does not meet threshold', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:insurance.example.com',
                nonce: 'nonce-insurance-456',
                purpose: 'Age verification for senior benefits',
                predicates: [CommonPredicates.ageAtLeast(65)],  // User is ~30
                timestamp: new Date().toISOString()
            };

            const result = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            expect(result.proof.allPassed).toBe(false);
            expect(result.proof.evaluations[0].result).toBe(false);
            expect(result.proof.evaluations[0].reasonCode).toBe('CRITERIA_NOT_MET');
        });

        it('evaluates residency predicate', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:eu-service.example.com',
                nonce: 'nonce-eu-789',
                purpose: 'EU residency check',
                predicates: [CommonPredicates.euResident()],
                timestamp: new Date().toISOString()
            };

            const result = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            expect(result.proof.allPassed).toBe(true);
            expect(result.proof.evaluations[0].result).toBe(true);
        });

        it('evaluates multiple predicates (AND semantics)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:multi.example.com',
                nonce: 'nonce-multi-000',
                purpose: 'Age + EU residency check',
                predicates: [
                    CommonPredicates.ageAtLeast(18),
                    CommonPredicates.euResident()
                ],
                timestamp: new Date().toISOString()
            };

            const result = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            expect(result.proof.allPassed).toBe(true);
            expect(result.proof.evaluations).toHaveLength(2);
            expect(result.proof.evaluations[0].result).toBe(true);
            expect(result.proof.evaluations[1].result).toBe(true);
        });

        it('fails if one predicate not met (AND semantics)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:strict.example.com',
                nonce: 'nonce-strict-111',
                purpose: 'Age 65+ and EU resident',
                predicates: [
                    CommonPredicates.ageAtLeast(65),  // FAILS (user is ~30)
                    CommonPredicates.euResident()     // PASSES
                ],
                timestamp: new Date().toISOString()
            };

            const result = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            expect(result.proof.allPassed).toBe(false);
            expect(result.proof.evaluations[0].result).toBe(false);
            expect(result.proof.evaluations[1].result).toBe(true);
        });

        it('throws on missing nonce (security violation)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:hacker.example.com',
                nonce: '',
                purpose: 'Malicious',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            await expect(
                evaluatePredicates(mockCredential, request, mockWalletSign)
            ).rejects.toThrow('SECURITY_VIOLATION');
        });

        it('throws on missing verifierDid (security violation)', async () => {
            const request: PredicateRequest = {
                verifierDid: '',
                nonce: 'nonce-bad-222',
                purpose: 'Malicious',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            await expect(
                evaluatePredicates(mockCredential, request, mockWalletSign)
            ).rejects.toThrow('SECURITY_VIOLATION');
        });
    });

    // ========================================================================
    // VERIFIER SIDE: Validate Predicate Result (Server-Side)
    // ========================================================================

    describe('Verifier: verifyPredicateResult()', () => {

        it('validates a legitimate predicate result', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:shop.example.com',
                nonce: 'nonce-shop-333',
                purpose: 'Age verification',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            const walletResult = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            const allowedHashes = await buildAllowedPredicateSet([
                CommonPredicates.ageAtLeast(18)
            ]);

            const verification = await verifyPredicateResult(
                walletResult,
                request,
                allowedHashes,
                mockVerifierVerify
            );

            expect(verification.valid).toBe(true);
            expect(verification.errors).toHaveLength(0);
        });

        it('detects verifier DID mismatch (anti-poaching)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:shop.example.com',
                nonce: 'nonce-shop-444',
                purpose: 'Age verification',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            const walletResult = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            const attackerRequest: PredicateRequest = {
                ...request,
                verifierDid: 'did:web:attacker.example.com'
            };

            const allowedHashes = await buildAllowedPredicateSet([
                CommonPredicates.ageAtLeast(18)
            ]);

            const verification = await verifyPredicateResult(
                walletResult,
                attackerRequest,
                allowedHashes,
                mockVerifierVerify
            );

            expect(verification.valid).toBe(false);
            expect(verification.errors.some(e => e.includes('Verifier DID mismatch'))).toBe(true);
        });

        it('detects nonce mismatch (anti-replay)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:shop.example.com',
                nonce: 'nonce-shop-555',
                purpose: 'Age verification',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            const walletResult = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            const attackerRequest: PredicateRequest = {
                ...request,
                nonce: 'nonce-shop-different'
            };

            const allowedHashes = await buildAllowedPredicateSet([
                CommonPredicates.ageAtLeast(18)
            ]);

            const verification = await verifyPredicateResult(
                walletResult,
                attackerRequest,
                allowedHashes,
                mockVerifierVerify
            );

            expect(verification.valid).toBe(false);
            expect(verification.errors.some(e => e.includes('Nonce mismatch'))).toBe(true);
        });

        it('detects request hash mismatch (tampered request)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:shop.example.com',
                nonce: 'nonce-shop-666',
                purpose: 'Age verification',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            const walletResult = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            const tamperedRequest: PredicateRequest = {
                ...request,
                predicates: [CommonPredicates.ageAtLeast(21)]
            };

            const allowedHashes = await buildAllowedPredicateSet([
                CommonPredicates.ageAtLeast(18),
                CommonPredicates.ageAtLeast(21)
            ]);

            const verification = await verifyPredicateResult(
                walletResult,
                tamperedRequest,
                allowedHashes,
                mockVerifierVerify
            );

            expect(verification.valid).toBe(false);
            expect(verification.errors.some(e => e.includes('Request hash mismatch'))).toBe(true);
        });

        it('detects unknown predicate hash (policy enforcement)', async () => {
            const request: PredicateRequest = {
                verifierDid: 'did:web:shop.example.com',
                nonce: 'nonce-shop-777',
                purpose: 'Age verification',
                predicates: [CommonPredicates.ageAtLeast(18)],
                timestamp: new Date().toISOString()
            };

            const walletResult = await evaluatePredicates(
                mockCredential,
                request,
                mockWalletSign
            );

            // Verifier only accepts ageAtLeast(21), not 18
            const allowedHashes = await buildAllowedPredicateSet([
                CommonPredicates.ageAtLeast(21)
            ]);

            const verification = await verifyPredicateResult(
                walletResult,
                request,
                allowedHashes,
                mockVerifierVerify
            );

            expect(verification.valid).toBe(false);
            expect(verification.errors.some(e => e.includes('Unknown predicate hash'))).toBe(true);
        });
    });

    // ========================================================================
    // CANONICALIZATION: Deterministic Hashing
    // ========================================================================

    describe('Canonicalization: Deterministic hashing', () => {

        it('produces identical hashes for semantically equivalent predicates', async () => {
            const pred1 = CommonPredicates.ageAtLeast(18);
            const pred2 = CommonPredicates.ageAtLeast(18);

            const hash1 = await hashPredicateAsync(pred1);
            const hash2 = await hashPredicateAsync(pred2);

            expect(hash1).toBe(hash2);
        });

        it('produces identical hashes for requests with different predicate order', async () => {
            const request1: PredicateRequest = {
                verifierDid: 'did:web:test.com',
                nonce: 'nonce-test',
                purpose: 'Test',
                predicates: [
                    CommonPredicates.ageAtLeast(18),
                    CommonPredicates.euResident()
                ],
                timestamp: '2025-01-28T10:00:00Z'
            };

            const request2: PredicateRequest = {
                verifierDid: 'did:web:test.com',
                nonce: 'nonce-test',
                purpose: 'Test',
                predicates: [
                    CommonPredicates.euResident(),
                    CommonPredicates.ageAtLeast(18)
                ],
                timestamp: '2025-01-28T10:00:00Z'
            };

            const hash1 = await hashRequestAsync(request1);
            const hash2 = await hashRequestAsync(request2);

            expect(hash1).toBe(hash2);
        });
    });
});
