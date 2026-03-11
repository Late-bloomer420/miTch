import { describe, it, expect, beforeEach } from 'vitest';
import { generateNullifier } from '@mitch/predicates';
import type { AdVerificationResponse, AdVerificationRequest } from '@mitch/shared-types';
import { AdTechVerifier, verifyAdResponse } from '../src/ad-verifier';
import { InMemoryNullifierStore } from '../src/ad-nullifier-store';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VERIFIER_DID = 'did:web:ads.test-verifier.com';
const SCOPE_ID = 'campaign-test-2026';
const USER_SEED = new Uint8Array(32).fill(0xab);

function makeNullifier() {
    return generateNullifier({ userSeed: USER_SEED, verifierDid: VERIFIER_DID, scopeId: SCOPE_ID });
}

function makeResponse(overrides: Partial<AdVerificationResponse> = {}): AdVerificationResponse {
    const n = makeNullifier();
    const now = new Date();
    const validUntil = new Date(now.getTime() + 60_000).toISOString();

    return {
        verdict: 'ALLOW',
        predicateResults: [],
        nullifier: { value: n.nullifier, scopeBinding: n.scopeBinding, boundVerifierDid: VERIFIER_DID },
        bindingProof: 'mock-binding-proof',
        signature: 'mock-signature',
        timestamp: now.toISOString(),
        validUntil,
        ...overrides,
    };
}

function makeRequest(overrides: Partial<AdVerificationRequest> = {}): AdVerificationRequest {
    return {
        verifierDid: VERIFIER_DID,
        scopeId: SCOPE_ID,
        predicates: [{ type: 'age_threshold', minAge: 18 }],
        nonce: 'test-nonce-123',
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// InMemoryNullifierStore
// ---------------------------------------------------------------------------

describe('InMemoryNullifierStore', () => {
    let store: InMemoryNullifierStore;

    beforeEach(() => {
        store = new InMemoryNullifierStore();
    });

    it('starts with zero count for unknown nullifier', async () => {
        expect(await store.getCount('unknown', SCOPE_ID)).toBe(0);
        expect(await store.exists('unknown', SCOPE_ID)).toBe(false);
    });

    it('records a nullifier and marks it as existing', async () => {
        await store.record('null-1', SCOPE_ID);
        expect(await store.exists('null-1', SCOPE_ID)).toBe(true);
        expect(await store.getCount('null-1', SCOPE_ID)).toBe(1);
    });

    it('increments count atomically', async () => {
        const c1 = await store.incrementCount('null-1', SCOPE_ID);
        const c2 = await store.incrementCount('null-1', SCOPE_ID);
        const c3 = await store.incrementCount('null-1', SCOPE_ID);
        expect(c1).toBe(1);
        expect(c2).toBe(2);
        expect(c3).toBe(3);
        expect(await store.getCount('null-1', SCOPE_ID)).toBe(3);
    });

    it('scopes counts per scopeId', async () => {
        await store.incrementCount('null-1', 'scope-a');
        await store.incrementCount('null-1', 'scope-a');
        await store.incrementCount('null-1', 'scope-b');
        expect(await store.getCount('null-1', 'scope-a')).toBe(2);
        expect(await store.getCount('null-1', 'scope-b')).toBe(1);
    });

    it('deletes a nullifier (GDPR Art. 17 erasure)', async () => {
        await store.incrementCount('null-1', SCOPE_ID);
        await store.delete('null-1', SCOPE_ID);
        expect(await store.exists('null-1', SCOPE_ID)).toBe(false);
        expect(await store.getCount('null-1', SCOPE_ID)).toBe(0);
    });

    it('record is idempotent', async () => {
        await store.record('null-1', SCOPE_ID);
        await store.record('null-1', SCOPE_ID);
        expect(await store.getCount('null-1', SCOPE_ID)).toBe(1);
    });
});

// ---------------------------------------------------------------------------
// AdTechVerifier — request creation
// ---------------------------------------------------------------------------

describe('AdTechVerifier.createRequest', () => {
    it('creates a request with correct verifierDid and scopeId', () => {
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID });
        const req = verifier.createRequest({
            scopeId: SCOPE_ID,
            predicates: [{ type: 'age_threshold', minAge: 18 }],
        });
        expect(req.verifierDid).toBe(VERIFIER_DID);
        expect(req.scopeId).toBe(SCOPE_ID);
        expect(req.predicates).toHaveLength(1);
        expect(req.nonce).toBeTruthy();
        expect(req.expiresAt).toBeTruthy();
    });

    it('each request has a unique nonce', () => {
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID });
        const nonces = new Set(
            Array.from({ length: 10 }, () =>
                verifier.createRequest({ scopeId: SCOPE_ID, predicates: [] }).nonce
            )
        );
        expect(nonces.size).toBe(10);
    });

    it('respects custom TTL', () => {
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID });
        const req = verifier.createRequest({ scopeId: SCOPE_ID, predicates: [], ttlSeconds: 60 });
        const diff = new Date(req.expiresAt).getTime() - Date.now();
        expect(diff).toBeGreaterThan(55_000);
        expect(diff).toBeLessThan(65_000);
    });
});

// ---------------------------------------------------------------------------
// verifyAdResponse (standalone — preferred path)
// ---------------------------------------------------------------------------

describe('verifyAdResponse', () => {
    it('accepts a valid ALLOW response', () => {
        const request = makeRequest();
        const response = makeResponse();
        const result = verifyAdResponse(response, request, VERIFIER_DID);
        expect(result.valid).toBe(true);
        expect(result.verdict).toBe('ALLOW');
        expect(result.nullifier).toBeTruthy();
        expect(result.errors).toHaveLength(0);
    });

    it('rejects an expired response', () => {
        const request = makeRequest();
        const response = makeResponse({
            validUntil: new Date(Date.now() - 200_000).toISOString(),
        });
        const result = verifyAdResponse(response, request, VERIFIER_DID);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('expired'))).toBe(true);
    });

    it('rejects a response with future timestamp', () => {
        const request = makeRequest();
        const response = makeResponse({
            timestamp: new Date(Date.now() + 300_000).toISOString(),
        });
        const result = verifyAdResponse(response, request, VERIFIER_DID);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('future'))).toBe(true);
    });

    it('rejects when nullifier is bound to wrong verifier', () => {
        const request = makeRequest();
        const response = makeResponse({
            nullifier: {
                value: makeNullifier().nullifier,
                scopeBinding: makeNullifier().scopeBinding,
                boundVerifierDid: 'did:web:other-verifier.com',  // wrong DID
            },
        });
        const result = verifyAdResponse(response, request, VERIFIER_DID);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('wrong verifier'))).toBe(true);
    });

    it('rejects tampered scope binding', () => {
        const request = makeRequest();
        const response = makeResponse({
            nullifier: {
                value: makeNullifier().nullifier,
                scopeBinding: 'tampered-scope-binding-value',
                boundVerifierDid: VERIFIER_DID,
            },
        });
        const result = verifyAdResponse(response, request, VERIFIER_DID);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('Scope binding'))).toBe(true);
    });

    it('passes DENY response without nullifier check', () => {
        const request = makeRequest();
        const response = makeResponse({
            verdict: 'DENY',
            denyReason: 'BUDGET_EXHAUSTED',
            nullifier: undefined,
        });
        const result = verifyAdResponse(response, request, VERIFIER_DID);
        expect(result.valid).toBe(true);
        expect(result.verdict).toBe('DENY');
        expect(result.nullifier).toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
// Frequency cap
// ---------------------------------------------------------------------------

describe('AdTechVerifier frequency cap', () => {
    it('allows impression when under cap', async () => {
        const store = new InMemoryNullifierStore();
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID, nullifierStore: store });
        const { nullifier } = makeNullifier();

        const check = await verifier.checkFrequencyCap(nullifier, SCOPE_ID, 5);
        expect(check.allowed).toBe(true);
        expect(check.impressions).toBe(0);
    });

    it('blocks impression when at cap', async () => {
        const store = new InMemoryNullifierStore();
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID, nullifierStore: store });
        const { nullifier } = makeNullifier();

        // Fill the cap
        for (let i = 0; i < 5; i++) {
            await verifier.recordImpression(nullifier, SCOPE_ID);
        }

        const check = await verifier.checkFrequencyCap(nullifier, SCOPE_ID, 5);
        expect(check.allowed).toBe(false);
        expect(check.impressions).toBe(5);
    });

    it('recordImpression returns new count', async () => {
        const store = new InMemoryNullifierStore();
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID, nullifierStore: store });
        const { nullifier } = makeNullifier();

        expect(await verifier.recordImpression(nullifier, SCOPE_ID)).toBe(1);
        expect(await verifier.recordImpression(nullifier, SCOPE_ID)).toBe(2);
    });

    it('allows when no store configured', async () => {
        const verifier = new AdTechVerifier({ verifierDid: VERIFIER_DID });
        const check = await verifier.checkFrequencyCap('any-nullifier', SCOPE_ID, 5);
        expect(check.allowed).toBe(true);
    });
});
