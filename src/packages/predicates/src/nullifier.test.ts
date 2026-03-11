import { describe, it, expect } from 'vitest';
import { generateNullifier, verifyNullifierScope } from './nullifier';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeSeed(fill: number = 0x42): Uint8Array {
    return new Uint8Array(32).fill(fill);
}

const VERIFIER_A = 'did:web:ads.verifier-a.com';
const VERIFIER_B = 'did:web:ads.verifier-b.com';
const SCOPE_CAMPAIGN_1 = 'campaign-spring-2026';
const SCOPE_CAMPAIGN_2 = 'campaign-summer-2026';

// ---------------------------------------------------------------------------
// Nullifier Generation
// ---------------------------------------------------------------------------

describe('generateNullifier', () => {
    it('produces deterministic output for same input', () => {
        const seed = makeSeed();
        const r1 = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        const r2 = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        expect(r1.nullifier).toBe(r2.nullifier);
        expect(r1.scopeBinding).toBe(r2.scopeBinding);
    });

    it('produces different nullifiers for different scope IDs', () => {
        const seed = makeSeed();
        const r1 = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        const r2 = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_2 });
        expect(r1.nullifier).not.toBe(r2.nullifier);
    });

    it('produces different nullifiers for different verifier DIDs (cross-verifier anti-correlation)', () => {
        const seed = makeSeed();
        const r1 = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        const r2 = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_B, scopeId: SCOPE_CAMPAIGN_1 });
        expect(r1.nullifier).not.toBe(r2.nullifier);
    });

    it('produces different nullifiers for different user seeds', () => {
        const r1 = generateNullifier({ userSeed: makeSeed(0x11), verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        const r2 = generateNullifier({ userSeed: makeSeed(0x22), verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        expect(r1.nullifier).not.toBe(r2.nullifier);
    });

    it('returns a base64url string (no +, /, = characters)', () => {
        const r = generateNullifier({ userSeed: makeSeed(), verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        expect(r.nullifier).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(r.scopeBinding).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('returns boundVerifierDid matching input', () => {
        const r = generateNullifier({ userSeed: makeSeed(), verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        expect(r.boundVerifierDid).toBe(VERIFIER_A);
    });

    it('rejects userSeed shorter than 32 bytes', () => {
        expect(() =>
            generateNullifier({ userSeed: new Uint8Array(16), verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 })
        ).toThrow('userSeed must be exactly 32 bytes');
    });

    it('rejects userSeed longer than 32 bytes', () => {
        expect(() =>
            generateNullifier({ userSeed: new Uint8Array(64), verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 })
        ).toThrow('userSeed must be exactly 32 bytes');
    });
});

// ---------------------------------------------------------------------------
// Scope Binding Verification
// ---------------------------------------------------------------------------

describe('verifyNullifierScope', () => {
    it('verifies a correct scope binding', () => {
        const { nullifier, scopeBinding } = generateNullifier({
            userSeed: makeSeed(),
            verifierDid: VERIFIER_A,
            scopeId: SCOPE_CAMPAIGN_1,
        });
        const result = verifyNullifierScope(nullifier, VERIFIER_A, SCOPE_CAMPAIGN_1, scopeBinding);
        expect(result.valid).toBe(true);
        expect(result.reason).toBeUndefined();
    });

    it('rejects binding when verifier DID does not match', () => {
        const { nullifier, scopeBinding } = generateNullifier({
            userSeed: makeSeed(),
            verifierDid: VERIFIER_A,
            scopeId: SCOPE_CAMPAIGN_1,
        });
        // Attempting to verify with a different verifier DID
        const result = verifyNullifierScope(nullifier, VERIFIER_B, SCOPE_CAMPAIGN_1, scopeBinding);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('Scope binding mismatch');
    });

    it('rejects binding when scope ID does not match', () => {
        const { nullifier, scopeBinding } = generateNullifier({
            userSeed: makeSeed(),
            verifierDid: VERIFIER_A,
            scopeId: SCOPE_CAMPAIGN_1,
        });
        // Attempting to verify with a different scope
        const result = verifyNullifierScope(nullifier, VERIFIER_A, SCOPE_CAMPAIGN_2, scopeBinding);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('Scope binding mismatch');
    });

    it('rejects a tampered scope binding', () => {
        const { nullifier } = generateNullifier({
            userSeed: makeSeed(),
            verifierDid: VERIFIER_A,
            scopeId: SCOPE_CAMPAIGN_1,
        });
        const result = verifyNullifierScope(nullifier, VERIFIER_A, SCOPE_CAMPAIGN_1, 'tampered-binding-value');
        expect(result.valid).toBe(false);
    });

    it('returns false for inputs that do not match', () => {
        // Buffer.from silently ignores invalid base64 chars — result is a mismatch, not a throw
        const result = verifyNullifierScope('completely-wrong-value', VERIFIER_A, SCOPE_CAMPAIGN_1, 'also-wrong');
        expect(result.valid).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// Cross-Verifier Isolation (ADR-ADTECH-001 key property)
// ---------------------------------------------------------------------------

describe('Cross-verifier isolation', () => {
    it('verifier A cannot use verifier B nullifier for same scope', () => {
        const seed = makeSeed();

        const forA = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_A, scopeId: SCOPE_CAMPAIGN_1 });
        const forB = generateNullifier({ userSeed: seed, verifierDid: VERIFIER_B, scopeId: SCOPE_CAMPAIGN_1 });

        // Verifier A's nullifier is invalid when verified against verifier B's scope
        const crossCheck = verifyNullifierScope(forA.nullifier, VERIFIER_B, SCOPE_CAMPAIGN_1, forA.scopeBinding);
        expect(crossCheck.valid).toBe(false);

        // Each nullifier is valid only for its own verifier
        expect(verifyNullifierScope(forA.nullifier, VERIFIER_A, SCOPE_CAMPAIGN_1, forA.scopeBinding).valid).toBe(true);
        expect(verifyNullifierScope(forB.nullifier, VERIFIER_B, SCOPE_CAMPAIGN_1, forB.scopeBinding).valid).toBe(true);
    });
});
