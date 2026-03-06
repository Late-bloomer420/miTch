import { describe, it, expect } from 'vitest';
import { canonicalPayload, canonicalizeRequest } from '../binding/canonicalize';
import type { VerificationRequestV0 } from '../types/api';

const REQ: VerificationRequestV0 = {
    version: 'v0',
    requestId: 'req-canon-001',
    rp: { id: 'shop.at', audience: 'mitch-wallet' },
    purpose: 'age_check',
    claims: [
        { type: 'predicate', name: 'over_18', value: true },
        { type: 'predicate', name: 'age', value: 18 },
    ],
    proofBundle: { format: 'sd-jwt', proof: 'ppp', alg: 'ES256' },
    binding: {
        nonce: 'n1',
        requestHash: 'h1',
        expiresAt: '2026-12-31T00:00:00Z',
    },
    policyRef: 'pol-v1',
};

describe('canonicalize', () => {
    it('canonicalizeRequest produces stable JSON string', () => {
        const s1 = canonicalizeRequest(REQ);
        const s2 = canonicalizeRequest(REQ);
        expect(s1).toBe(s2);
    });

    it('object keys are sorted alphabetically', () => {
        const payload = canonicalPayload(REQ);
        const keys = Object.keys(payload);
        expect(keys).toEqual([...keys].sort());
    });

    it('different nonces produce different strings', () => {
        const req2 = { ...REQ, binding: { ...REQ.binding, nonce: 'n2' } };
        expect(canonicalizeRequest(REQ)).not.toBe(canonicalizeRequest(req2));
    });

    it('extracts only known fields (strips extra fields)', () => {
        const reqWithExtra = { ...REQ, extra: 'ignored' } as any;
        const payload = canonicalPayload(reqWithExtra);
        expect('extra' in payload).toBe(false);
    });

    it('NFC normalizes unicode strings', () => {
        // Compose vs. decompose forms of "ä"
        const composed = '\u00e4';    // ä (precomposed)
        const decomposed = '\u0061\u0308'; // a + combining umlaut
        expect(composed).not.toBe(decomposed);

        const r1 = { ...REQ, purpose: composed };
        const r2 = { ...REQ, purpose: decomposed };
        // After NFC normalization both should produce same canonical string
        expect(canonicalizeRequest(r1)).toBe(canonicalizeRequest(r2));
    });
});
