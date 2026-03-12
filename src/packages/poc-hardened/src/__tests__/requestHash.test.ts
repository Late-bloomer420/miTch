import { describe, it, expect } from 'vitest';
import { computeRequestHash } from '../binding/requestHash';
import type { VerificationRequestV0 } from '../types/api';

const BASE_REQ: VerificationRequestV0 = {
    version: 'v0',
    requestId: 'req-hash-001',
    rp: { id: 'shop.at', audience: 'mitch-wallet' },
    purpose: 'age_verification',
    claims: [{ type: 'predicate', name: 'over_18', value: true }],
    proofBundle: { format: 'sd-jwt', proof: 'xxx', alg: 'ES256' },
    binding: {
        nonce: 'nonce-abc',
        requestHash: 'placeholder',
        expiresAt: '2026-12-31T00:00:00Z',
    },
    policyRef: 'policy-v1',
};

describe('computeRequestHash', () => {
    it('returns a string', () => {
        const hash = computeRequestHash(BASE_REQ);
        expect(typeof hash).toBe('string');
    });

    it('is deterministic — same input yields same hash', () => {
        expect(computeRequestHash(BASE_REQ)).toBe(computeRequestHash(BASE_REQ));
    });

    it('different nonce produces different hash', () => {
        const req2 = { ...BASE_REQ, binding: { ...BASE_REQ.binding, nonce: 'nonce-xyz' } };
        expect(computeRequestHash(BASE_REQ)).not.toBe(computeRequestHash(req2));
    });

    it('different requestId produces different hash', () => {
        const req2 = { ...BASE_REQ, requestId: 'req-hash-002' };
        expect(computeRequestHash(BASE_REQ)).not.toBe(computeRequestHash(req2));
    });

    it('different purpose produces different hash', () => {
        const req2 = { ...BASE_REQ, purpose: 'income_check' };
        expect(computeRequestHash(BASE_REQ)).not.toBe(computeRequestHash(req2));
    });

    it('output is base64url (no + or / or =)', () => {
        const hash = computeRequestHash(BASE_REQ);
        expect(hash).not.toContain('+');
        expect(hash).not.toContain('/');
        expect(hash).not.toContain('=');
    });

    it('output has SHA-256 length (43 base64url chars for 32 bytes)', () => {
        const hash = computeRequestHash(BASE_REQ);
        // SHA-256 = 32 bytes → 43 base64url chars (no padding)
        expect(hash.length).toBe(43);
    });

    it('multiple claims affect the hash', () => {
        const req2 = {
            ...BASE_REQ,
            claims: [
                { type: 'predicate' as const, name: 'over_18', value: true },
                { type: 'predicate' as const, name: 'eu_resident', value: true },
            ],
        };
        expect(computeRequestHash(BASE_REQ)).not.toBe(computeRequestHash(req2));
    });
});
