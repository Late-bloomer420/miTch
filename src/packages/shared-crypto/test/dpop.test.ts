 
import { describe, it, expect, beforeAll } from 'vitest';
import {
    generateDPoPKeyPair,
    createDPoPProof,
    validateDPoPProof,
    computeDPoPThumbprint,
    type DPoPKeyPair,
} from '../src/dpop';

let keyPair: DPoPKeyPair;

beforeAll(async () => {
    keyPair = await generateDPoPKeyPair();
});

const TOKEN_ENDPOINT = 'https://as.example.com/token';
const RESOURCE_ENDPOINT = 'https://rs.example.com/resource';

// ─── E-05.1: DPoP Proof Generation ───────────────────────────────────────────

describe('DPoP Proof Generation', () => {
    it('generates a valid dpop+jwt', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT },
            keyPair
        );
        expect(proof).toMatch(/^eyJ/);

        const headerB64 = proof.split('.')[0];
        const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(header.typ).toBe('dpop+jwt');
        expect(header.alg).toBe('ES256');
        expect(header.jwk).toBeDefined();
        expect(header.jwk.d).toBeUndefined(); // no private key
    });

    it('includes required payload claims (jti, htm, htu, iat)', async () => {
        const proof = await createDPoPProof(
            { htm: 'GET', htu: RESOURCE_ENDPOINT },
            keyPair
        );
        const payloadB64 = proof.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.jti).toBeDefined();
        expect(payload.htm).toBe('GET');
        expect(typeof payload.iat).toBe('number');
        expect(payload.htu).toContain('rs.example.com');
    });

    it('includes nonce when provided', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT, nonce: 'server-nonce-xyz' },
            keyPair
        );
        const payloadB64 = proof.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.nonce).toBe('server-nonce-xyz');
    });

    it('includes ath when access token provided', async () => {
        const proof = await createDPoPProof(
            { htm: 'GET', htu: RESOURCE_ENDPOINT, accessToken: 'my-access-token' },
            keyPair
        );
        const payloadB64 = proof.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.ath).toBeDefined();
        expect(typeof payload.ath).toBe('string');
        expect(payload.ath.length).toBeGreaterThan(20);
    });
});

// ─── E-05.2: DPoP Proof Validation ───────────────────────────────────────────

describe('DPoP Proof Validation', () => {
    it('validates a valid DPoP proof', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT },
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
        });
        expect(result.ok).toBe(true);
        expect(result.payload?.htm).toBe('POST');
        expect(result.publicKey).toBeDefined();
    });

    it('rejects proof with wrong htm', async () => {
        const proof = await createDPoPProof(
            { htm: 'GET', htu: TOKEN_ENDPOINT },
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('htm mismatch'))).toBe(true);
    });

    it('rejects proof with wrong htu', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT },
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: 'https://evil.example.com/token',
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('htu mismatch'))).toBe(true);
    });

    it('detects replay via jti tracking', async () => {
        const seenJtis = new Set<string>();
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT },
            keyPair
        );
        // First use: OK
        const r1 = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
            seenJtis,
        });
        expect(r1.ok).toBe(true);

        // Second use of same proof: replay detected
        const r2 = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
            seenJtis,
        });
        expect(r2.ok).toBe(false);
        expect(r2.errors.some(e => e.includes('Replay detected'))).toBe(true);
    });

    it('validates nonce binding', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT, nonce: 'correct-nonce' },
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
            expectedNonce: 'correct-nonce',
        });
        expect(result.ok).toBe(true);
    });

    it('rejects proof with wrong nonce', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT, nonce: 'old-nonce' },
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
            expectedNonce: 'new-nonce',
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('nonce mismatch'))).toBe(true);
    });

    it('rejects proof missing nonce when server requires it', async () => {
        const proof = await createDPoPProof(
            { htm: 'POST', htu: TOKEN_ENDPOINT }, // no nonce
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'POST',
            expectedHtu: TOKEN_ENDPOINT,
            expectedNonce: 'required-nonce',
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('Missing nonce'))).toBe(true);
    });

    it('validates ath (access token hash) binding', async () => {
        const accessToken = 'dGhpcyBpcyBhIHRlc3QgdG9rZW4';
        const proof = await createDPoPProof(
            { htm: 'GET', htu: RESOURCE_ENDPOINT, accessToken },
            keyPair
        );
        const result = await validateDPoPProof(proof, {
            expectedHtm: 'GET',
            expectedHtu: RESOURCE_ENDPOINT,
            accessToken,
        });
        expect(result.ok).toBe(true);
    });
});

// ─── E-05.3: DPoP Thumbprint ──────────────────────────────────────────────────

describe('DPoP Thumbprint', () => {
    it('computes consistent thumbprint for same key', async () => {
        const tp1 = await computeDPoPThumbprint(keyPair.publicKeyJWK);
        const tp2 = await computeDPoPThumbprint(keyPair.publicKeyJWK);
        expect(tp1).toBe(tp2);
        expect(tp1.length).toBeGreaterThan(20);
    });

    it('produces different thumbprints for different keys', async () => {
        const kp2 = await generateDPoPKeyPair();
        const tp1 = await computeDPoPThumbprint(keyPair.publicKeyJWK);
        const tp2 = await computeDPoPThumbprint(kp2.publicKeyJWK);
        expect(tp1).not.toBe(tp2);
    });
});
