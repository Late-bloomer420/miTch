import { describe, it, expect } from 'vitest';
import { BrowserVerifier } from '../src/BrowserVerifier.js';

describe('BrowserVerifier (T-85)', () => {
    it('should create ephemeral session with valid keys', async () => {
        const verifier = new BrowserVerifier({
            verifierName: "Test Store",
            purpose: "Age Verification",
            requestedClaims: ["age"],
            requestedProvenClaims: ["age >= 18"]
        });

        const session = await verifier.createSession();

        // Verify session structure
        expect(session.sessionId).toMatch(/^[a-f0-9-]{36}$/); // UUID format
        expect(session.nonce).toHaveLength(64); // 32 bytes hex
        expect(session.publicKey).toBeDefined();
        expect(session.publicKey.kty).toBe('EC');
        expect(session.publicKey.crv).toBe('P-256');
        expect(session.challengeUrl).toContain('mitch://verify');
        expect(session.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should generate unique sessions', async () => {
        const verifier = new BrowserVerifier({
            verifierName: "Test Store",
            purpose: "Test",
            requestedClaims: ["test"]
        });

        const session1 = await verifier.createSession();
        const session2 = await verifier.createSession();

        // Sessions must be unique
        expect(session1.sessionId).not.toBe(session2.sessionId);
        expect(session1.nonce).not.toBe(session2.nonce);
        expect(session1.publicKey.x).not.toBe(session2.publicKey.x);
    });

    it('should include verifier info in challenge URL', async () => {
        const verifier = new BrowserVerifier({
            verifierName: "Joe's Liquor Store",
            purpose: "Age Check",
            requestedClaims: ["age"],
            requestedProvenClaims: ["age >= 18"]
        });

        const session = await verifier.createSession();
        const url = new URL(session.challengeUrl.replace('mitch://', 'https://'));

        expect(url.searchParams.get('verifier')).toBe("Joe's Liquor Store");
        expect(url.searchParams.get('purpose')).toBe("Age Check");
        expect(url.searchParams.get('claims')).toBe("age");
        expect(url.searchParams.get('proven')).toBe("age >= 18");
    });

    it('should respect custom session timeout', async () => {
        const customTimeout = 10_000; // 10 seconds
        const verifier = new BrowserVerifier({
            verifierName: "Test",
            purpose: "Test",
            requestedClaims: ["test"],
            sessionTimeoutMs: customTimeout
        });

        const session = await verifier.createSession();
        const expectedExpiry = Date.now() + customTimeout;

        // Allow 100ms variance for execution time
        expect(session.expiresAt).toBeGreaterThan(expectedExpiry - 100);
        expect(session.expiresAt).toBeLessThan(expectedExpiry + 100);
    });

    it('should reject expired session during verification', async () => {
        const verifier = new BrowserVerifier({
            verifierName: "Test",
            purpose: "Test",
            requestedClaims: ["test"],
            sessionTimeoutMs: 1 // 1ms timeout
        });

        const session = await verifier.createSession();

        // Wait for expiration
        await new Promise(resolve => setTimeout(resolve, 10));

        // Try to verify (should fail)
        const result = await verifier.verifyResponse({
            sessionId: session.sessionId,
            encryptedPayload: "dummy",
            signature: "dummy",
            walletDid: "did:example:123"
        });

        expect(result.success).toBe(false);
        expect(result.error).toContain('expired');
    });
});
