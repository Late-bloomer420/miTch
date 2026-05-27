import { describe, it, expect } from 'vitest';
import { ProofEngine } from '../proof/ProofEngine';
import { PersonalDataVault } from '../vault/PersonalDataVault';
import type { ConsentDecision } from '../types/ConsentDecision';

const makeDecision = (overrides: Partial<ConsentDecision> = {}): ConsentDecision => ({
    requestId: 'req-001',
    allowed: true,
    reason: 'policy allows',
    decidedAt: Date.now(),
    constraints: { auditLog: true },
    ...overrides,
});

describe('ProofEngine.generateProof()', () => {
    const vault = new PersonalDataVault();
    const engine = new ProofEngine(vault);

    it('returns an invalid proof when decision is denied', () => {
        const proof = engine.generateProof(makeDecision({ allowed: false }), 'user_001', 'age');
        expect(proof.isValid).toBe(false);
        expect(proof.requestId).toBe('req-001');
    });

    it('returns a valid age_over_18 proof for user with age 27', () => {
        const proof = engine.generateProof(makeDecision(), 'user_001', 'age');
        expect(proof.isValid).toBe(true);
        expect(proof.proofType).toBe('age_over_18');
    });

    it('never exposes raw age value in the proof', () => {
        const proof = engine.generateProof(makeDecision(), 'user_001', 'age');
        const serialized = JSON.stringify(proof);
        expect(serialized).not.toContain('27');
    });

    it('returns a valid email_verified proof for a user with an email', () => {
        const proof = engine.generateProof(makeDecision(), 'user_001', 'email');
        expect(proof.isValid).toBe(true);
        expect(proof.proofType).toBe('email_verified');
    });

    it('never exposes raw email value in the proof', () => {
        const proof = engine.generateProof(makeDecision(), 'user_001', 'email');
        const serialized = JSON.stringify(proof);
        expect(serialized).not.toContain('user@example.local');
    });

    it('returns an invalid proof for an unknown category', () => {
        const proof = engine.generateProof(makeDecision(), 'user_001', 'passport_number');
        expect(proof.isValid).toBe(false);
    });

    it('returns an invalid proof for an unknown user', () => {
        const proof = engine.generateProof(makeDecision(), 'user_does_not_exist', 'age');
        expect(proof.isValid).toBe(false);
    });

    it('sets generatedAt to a recent timestamp', () => {
        const before = Date.now();
        const proof = engine.generateProof(makeDecision(), 'user_001', 'age');
        const after = Date.now();
        expect(proof.generatedAt).toBeGreaterThanOrEqual(before);
        expect(proof.generatedAt).toBeLessThanOrEqual(after);
    });

    it('sets expiresAt from decision constraints when provided', () => {
        const validUntil = Date.now() + 3600_000;
        const proof = engine.generateProof(
            makeDecision({ constraints: { validUntil, auditLog: true } }),
            'user_001',
            'age'
        );
        expect(proof.expiresAt).toBe(validUntil);
    });

    it('requestId in proof matches the decision requestId', () => {
        const proof = engine.generateProof(makeDecision({ requestId: 'custom-req-id' }), 'user_001', 'age');
        expect(proof.requestId).toBe('custom-req-id');
    });
});
