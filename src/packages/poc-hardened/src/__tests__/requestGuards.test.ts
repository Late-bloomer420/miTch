import { describe, it, expect } from 'vitest';
import { validateRequestSemantics } from '../api/requestGuards';
import type { VerificationRequestV0 } from '../types/api';

const VALID: VerificationRequestV0 = {
    version: 'v0',
    requestId: 'req-001',
    rp: { id: 'shop.at', audience: 'mitch-wallet' },
    purpose: 'age_verification',
    claims: [{ type: 'predicate', name: 'over_18', value: true }],
    proofBundle: { format: 'sd-jwt', proof: 'xxx', alg: 'ES256' },
    binding: {
        nonce: 'nonce-abc',
        requestHash: 'hash-abc',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
    },
    policyRef: 'policy-v1',
};

describe('validateRequestSemantics', () => {
    it('accepts valid request', () => {
        expect(validateRequestSemantics(VALID)).toEqual({ ok: true });
    });

    it('rejects empty claims array', () => {
        const r = validateRequestSemantics({ ...VALID, claims: [] });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('DENY_SCHEMA_MISSING_FIELD');
    });

    it('rejects non-predicate claim type', () => {
        const r = validateRequestSemantics({
            ...VALID,
            claims: [{ type: 'raw' as any, name: 'age', value: 18 }],
        });
        expect(r.ok).toBe(false);
    });

    it('rejects claim with empty name', () => {
        const r = validateRequestSemantics({
            ...VALID,
            claims: [{ type: 'predicate', name: '', value: true }],
        });
        expect(r.ok).toBe(false);
    });

    it('rejects null binding', () => {
        const r = validateRequestSemantics({
            ...VALID,
            binding: null as any,
        });
        expect(r.ok).toBe(false);
    });

    it('rejects null proofBundle', () => {
        const r = validateRequestSemantics({
            ...VALID,
            proofBundle: null as any,
        });
        expect(r.ok).toBe(false);
    });

    it('rejects invalid jurisdiction (empty string when present)', () => {
        const r = validateRequestSemantics({
            ...VALID,
            rp: { id: 'shop.at', audience: 'wallet', jurisdiction: '' },
        });
        expect(r.ok).toBe(false);
    });

    it('accepts valid jurisdiction string', () => {
        const r = validateRequestSemantics({
            ...VALID,
            rp: { id: 'shop.at', audience: 'wallet', jurisdiction: 'AT' },
        });
        expect(r.ok).toBe(true);
    });
});
