import { describe, it, expect } from 'vitest';
import { validateBinding, type BindingConfig } from '../binding/validateBinding';
import { computeRequestHash } from '../binding/requestHash';
import { InMemoryNonceStore } from '../binding/nonceStore';
import type { VerificationRequestV0 } from '../types/api';

const config: BindingConfig = {
    clockSkewSeconds: 90,
    nonceTtlSeconds: 300,
};

const makeFutureExpiry = (offsetMs = 600_000) =>
    new Date(Date.now() + offsetMs).toISOString();

const makePastExpiry = (offsetMs = 200_000) =>
    new Date(Date.now() - offsetMs).toISOString();

function makeRequest(overrides: Partial<VerificationRequestV0> = {}): VerificationRequestV0 {
    const base: VerificationRequestV0 = {
        version: 'v0',
        requestId: 'req-001',
        rp: { id: 'rp-001', audience: 'https://verifier.example.com' },
        purpose: 'age verification',
        claims: [{ type: 'predicate', name: 'age_over_18', value: true }],
        proofBundle: { format: 'vc+sd-jwt', proof: 'dummy-proof' },
        policyRef: 'policy-v1',
        binding: {
            nonce: 'nonce-abc-123',
            requestHash: '', // computed below
            expiresAt: makeFutureExpiry(),
        },
        ...overrides,
    };

    // Compute the real hash for the base (or overridden) request
    base.binding.requestHash = computeRequestHash(base);
    return base;
}

describe('validateBinding()', () => {
    it('returns { ok: true } for a valid request', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest();
        const result = await validateBinding(request, 'https://verifier.example.com', store, config);
        expect(result).toEqual({ ok: true });
    });

    it('DENY_BINDING_AUDIENCE_MISMATCH when runtimeAudience does not match rp.audience', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest();
        const result = await validateBinding(request, 'https://other.example.com', store, config);
        expect(result.ok).toBe(false);
        expect(result.code).toBe('DENY_BINDING_AUDIENCE_MISMATCH');
    });

    it('DENY_BINDING_EXPIRED when binding.expiresAt is in the past', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest({
            binding: {
                nonce: 'nonce-abc-123',
                requestHash: 'placeholder',
                expiresAt: makePastExpiry(),
            },
        });
        // Recompute hash after overriding binding fields
        request.binding.requestHash = computeRequestHash(request);

        const result = await validateBinding(request, 'https://verifier.example.com', store, config);
        expect(result.ok).toBe(false);
        expect(result.code).toBe('DENY_BINDING_EXPIRED');
    });

    it('DENY_BINDING_HASH_MISMATCH when requestHash does not match payload', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest();
        request.binding.requestHash = 'tampered-hash-value';

        const result = await validateBinding(request, 'https://verifier.example.com', store, config);
        expect(result.ok).toBe(false);
        expect(result.code).toBe('DENY_BINDING_HASH_MISMATCH');
    });

    it('{ ok: true } on first nonce use', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest();
        const result = await validateBinding(request, 'https://verifier.example.com', store, config);
        expect(result.ok).toBe(true);
    });

    it('DENY_BINDING_NONCE_REPLAY on second use of same nonce', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest();

        await validateBinding(request, 'https://verifier.example.com', store, config);
        const replay = await validateBinding(request, 'https://verifier.example.com', store, config);

        expect(replay.ok).toBe(false);
        expect(replay.code).toBe('DENY_BINDING_NONCE_REPLAY');
    });

    it('audience mismatch is checked before expiry (ordering)', async () => {
        const store = new InMemoryNonceStore();
        const request = makeRequest({
            binding: {
                nonce: 'nonce-abc-123',
                requestHash: 'placeholder',
                expiresAt: makePastExpiry(),
            },
        });
        request.binding.requestHash = computeRequestHash(request);

        // Wrong audience + expired — should fail on audience first
        const result = await validateBinding(request, 'https://wrong.example.com', store, config);
        expect(result.code).toBe('DENY_BINDING_AUDIENCE_MISMATCH');
    });
});
