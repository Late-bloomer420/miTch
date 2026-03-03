import { describe, test, expect, beforeEach } from 'vitest';
import {
    BindingNonceStore,
    generateNonce,
    DENY_BINDING_NONCE_UNKNOWN,
    DENY_BINDING_NONCE_REPLAY,
    DENY_BINDING_EXPIRED,
    DENY_BINDING_AUDIENCE_MISMATCH,
    DENY_SCHEMA_MISSING_FIELD,
    DENY_BINDING_HASH_MISMATCH,
} from '../src/nonce-store';
import {
    computeRequestHash,
    validateBinding,
    type PresentationRequest,
} from '../src/presentation-binding';

// ── Helpers ─────────────────────────────────────────────────────────────────

const AUDIENCE = 'did:mitch:verifier-liquor-store';
const NOW = 1709510400000; // Fixed timestamp for deterministic tests

function makeRequest(overrides: Partial<PresentationRequest> = {}): PresentationRequest {
    return {
        version: '1.0',
        requestId: 'req-001',
        rp: { id: 'liquor-store', audience: AUDIENCE },
        purpose: 'Age Verification',
        claims: ['age >= 18'],
        binding: {
            nonce: 'a'.repeat(64),
            expiresAt: new Date(NOW + 5 * 60 * 1000).toISOString(),
            requestHash: '', // Will be filled by helper
        },
        ...overrides,
    };
}

async function makeSignedRequest(
    overrides: Partial<PresentationRequest> = {}
): Promise<PresentationRequest> {
    const req = makeRequest(overrides);
    req.binding.requestHash = await computeRequestHash(req);
    return req;
}

// ── Nonce Generation ────────────────────────────────────────────────────────

describe('generateNonce', () => {
    test('produces 64 hex chars (32 bytes)', () => {
        const nonce = generateNonce();
        expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    });

    test('produces unique values', () => {
        const a = generateNonce();
        const b = generateNonce();
        expect(a).not.toBe(b);
    });
});

// ── NonceStore ──────────────────────────────────────────────────────────────

describe('BindingNonceStore', () => {
    let store: BindingNonceStore;

    beforeEach(() => {
        store = new BindingNonceStore({ ttlMs: 5 * 60 * 1000, clockSkewMs: 30_000 });
    });

    test('issue and consume — valid flow', () => {
        const { nonce } = store.issue(AUDIENCE, NOW);
        const result = store.consume(AUDIENCE, nonce, NOW);
        expect(result).toEqual({ ok: true });
    });

    test('replay same nonce → DENY', () => {
        const { nonce } = store.issue(AUDIENCE, NOW);
        store.consume(AUDIENCE, nonce, NOW);
        const replay = store.consume(AUDIENCE, nonce, NOW);
        expect(replay).toEqual({ ok: false, code: DENY_BINDING_NONCE_UNKNOWN });
    });

    test('unknown nonce → DENY', () => {
        const result = store.consume(AUDIENCE, 'nonexistent', NOW);
        expect(result).toEqual({ ok: false, code: DENY_BINDING_NONCE_UNKNOWN });
    });

    test('expired nonce (beyond skew) → DENY', () => {
        const { nonce } = store.issue(AUDIENCE, NOW);
        // Advance past TTL + clock skew
        const future = NOW + 5 * 60 * 1000 + 30_001;
        const result = store.consume(AUDIENCE, nonce, future);
        expect(result).toEqual({ ok: false, code: DENY_BINDING_EXPIRED });
    });

    test('nonce within clock skew → ALLOW', () => {
        const { nonce } = store.issue(AUDIENCE, NOW);
        // Just past TTL but within skew
        const future = NOW + 5 * 60 * 1000 + 15_000;
        const result = store.consume(AUDIENCE, nonce, future);
        expect(result).toEqual({ ok: true });
    });

    test('wrong audience → DENY', () => {
        const { nonce } = store.issue(AUDIENCE, NOW);
        const result = store.consume('did:mitch:evil-verifier', nonce, NOW);
        expect(result).toEqual({ ok: false, code: DENY_BINDING_NONCE_UNKNOWN });
    });

    test('register external nonce and consume', () => {
        const nonce = 'b'.repeat(64);
        const expiresAt = NOW + 300_000;
        store.register(AUDIENCE, nonce, expiresAt, NOW);
        expect(store.has(AUDIENCE, nonce, NOW)).toBe(true);
        const result = store.consume(AUDIENCE, nonce, NOW);
        expect(result).toEqual({ ok: true });
    });
});

// ── Canonicalization ────────────────────────────────────────────────────────

describe('computeRequestHash', () => {
    test('same input → same hash', async () => {
        const req = makeRequest();
        const h1 = await computeRequestHash(req);
        const h2 = await computeRequestHash(req);
        expect(h1).toBe(h2);
        expect(h1).toMatch(/^[0-9a-f]{64}$/);
    });

    test('different nonce → different hash', async () => {
        const req1 = makeRequest();
        const req2 = makeRequest({
            binding: { ...makeRequest().binding, nonce: 'b'.repeat(64) },
        });
        const h1 = await computeRequestHash(req1);
        const h2 = await computeRequestHash(req2);
        expect(h1).not.toBe(h2);
    });

    test('different audience → different hash', async () => {
        const req1 = makeRequest();
        const req2 = makeRequest({
            rp: { id: 'liquor-store', audience: 'did:mitch:other' },
        });
        expect(await computeRequestHash(req1)).not.toBe(await computeRequestHash(req2));
    });

    test('reordered claims → different hash (order-sensitive)', async () => {
        const req1 = makeRequest({ claims: ['a', 'b'] });
        const req2 = makeRequest({ claims: ['b', 'a'] });
        expect(await computeRequestHash(req1)).not.toBe(await computeRequestHash(req2));
    });
});

// ── Full Binding Validation ─────────────────────────────────────────────────

describe('validateBinding', () => {
    let store: BindingNonceStore;

    beforeEach(() => {
        store = new BindingNonceStore({ ttlMs: 5 * 60 * 1000, clockSkewMs: 30_000 });
    });

    test('valid presentation → ALLOW', async () => {
        const req = await makeSignedRequest();
        store.register(AUDIENCE, req.binding.nonce, NOW + 300_000, NOW);

        const result = await validateBinding(req, store, AUDIENCE, NOW);
        expect(result).toEqual({ ok: true });
    });

    test('replay same presentation → DENY', async () => {
        const req = await makeSignedRequest();
        store.register(AUDIENCE, req.binding.nonce, NOW + 300_000, NOW);

        // First attempt succeeds
        const r1 = await validateBinding(req, store, AUDIENCE, NOW);
        expect(r1.ok).toBe(true);

        // Re-register wouldn't happen in real flow; nonce is consumed
        // Second attempt with same nonce fails (nonce was consumed/removed)
        const r2 = await validateBinding(req, store, AUDIENCE, NOW);
        expect(r2).toEqual({ ok: false, code: DENY_BINDING_NONCE_UNKNOWN });
    });

    test('expired nonce → DENY', async () => {
        const pastExpiry = new Date(NOW - 60_000).toISOString();
        const req = await makeSignedRequest({
            binding: {
                nonce: 'c'.repeat(64),
                expiresAt: pastExpiry,
            },
        });
        store.register(AUDIENCE, req.binding.nonce, NOW - 60_000, NOW - 120_000);

        const result = await validateBinding(req, store, AUDIENCE, NOW);
        // Nonce expired and pruned
        expect(result.ok).toBe(false);
    });

    test('wrong audience → DENY', async () => {
        const req = await makeSignedRequest({
            rp: { id: 'liquor-store', audience: 'did:mitch:evil' },
        });
        store.register('did:mitch:evil', req.binding.nonce, NOW + 300_000, NOW);

        const result = await validateBinding(req, store, AUDIENCE, NOW);
        expect(result).toEqual({ ok: false, code: DENY_BINDING_AUDIENCE_MISMATCH });
    });

    test('tampered hash → DENY', async () => {
        const req = await makeSignedRequest();
        store.register(AUDIENCE, req.binding.nonce, NOW + 300_000, NOW);

        // Tamper with the hash
        req.binding.requestHash = 'f'.repeat(64);

        const result = await validateBinding(req, store, AUDIENCE, NOW);
        expect(result).toEqual({ ok: false, code: DENY_BINDING_HASH_MISMATCH });
    });

    test('missing required field → DENY', async () => {
        const req = await makeSignedRequest();
        // @ts-expect-error — intentional missing field
        req.version = '';

        const result = await validateBinding(req, store, AUDIENCE, NOW);
        expect(result).toEqual({ ok: false, code: DENY_SCHEMA_MISSING_FIELD });
    });

    test('clock skew beyond tolerance → DENY', async () => {
        const req = await makeSignedRequest({
            binding: {
                nonce: 'd'.repeat(64),
                expiresAt: new Date(NOW).toISOString(), // Expires exactly at NOW
            },
        });
        store.register(AUDIENCE, req.binding.nonce, NOW, NOW - 300_000);

        // 31 seconds past expiry, skew is ±30s
        const result = await validateBinding(req, store, AUDIENCE, NOW + 30_001);
        expect(result.ok).toBe(false);
    });
});
