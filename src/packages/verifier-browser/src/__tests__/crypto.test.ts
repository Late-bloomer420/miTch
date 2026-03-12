import { describe, it, expect } from 'vitest';
import {
    generateEphemeralKeyPair,
    generateNonce,
    generateSessionId,
    exportPublicKeyJWK,
    importPublicKeyJWK,
    verifySignature,
    sha256,
    decryptJWE,
    base64UrlToBuffer,
    bufferToBase64Url,
} from '../crypto';

// Node 20+ provides globalThis.crypto with WebCrypto

describe('generateEphemeralKeyPair', () => {
    it('returns a CryptoKeyPair with public and private keys', async () => {
        const kp = await generateEphemeralKeyPair();
        expect(kp).toBeDefined();
        expect(kp.publicKey).toBeDefined();
        expect(kp.privateKey).toBeDefined();
        expect(kp.publicKey.type).toBe('public');
        expect(kp.privateKey.type).toBe('private');
    });

    it('generates ECDSA P-256 keys', async () => {
        const kp = await generateEphemeralKeyPair();
        expect(kp.publicKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
        expect(kp.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
    });

    it('generates extractable keys', async () => {
        const kp = await generateEphemeralKeyPair();
        expect(kp.publicKey.extractable).toBe(true);
        expect(kp.privateKey.extractable).toBe(true);
    });

    it('private key has sign usage, public has verify', async () => {
        const kp = await generateEphemeralKeyPair();
        expect(kp.privateKey.usages).toContain('sign');
        expect(kp.publicKey.usages).toContain('verify');
    });

    it('generates unique key pairs each call', async () => {
        const kp1 = await generateEphemeralKeyPair();
        const kp2 = await generateEphemeralKeyPair();
        const jwk1 = await crypto.subtle.exportKey('jwk', kp1.publicKey);
        const jwk2 = await crypto.subtle.exportKey('jwk', kp2.publicKey);
        expect(jwk1.x).not.toBe(jwk2.x);
    });
});

describe('generateNonce', () => {
    it('returns a 64-character hex string (32 bytes)', () => {
        const nonce = generateNonce();
        expect(nonce).toHaveLength(64);
        expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    });

    it('generates unique nonces', () => {
        const n1 = generateNonce();
        const n2 = generateNonce();
        expect(n1).not.toBe(n2);
    });
});

describe('generateSessionId', () => {
    it('returns a valid UUID v4 format', () => {
        const id = generateSessionId();
        expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    });

    it('generates unique session IDs', () => {
        const ids = new Set(Array.from({ length: 10 }, () => generateSessionId()));
        expect(ids.size).toBe(10);
    });
});

describe('exportPublicKeyJWK / importPublicKeyJWK roundtrip', () => {
    it('exports public key to JWK format', async () => {
        const kp = await generateEphemeralKeyPair();
        const jwk = await exportPublicKeyJWK(kp.publicKey);
        expect(jwk.kty).toBe('EC');
        expect(jwk.crv).toBe('P-256');
        expect(jwk.x).toBeDefined();
        expect(jwk.y).toBeDefined();
        // Public key should not contain private component
        expect(jwk.d).toBeUndefined();
    });

    it('round-trips: export then import produces usable key', async () => {
        const kp = await generateEphemeralKeyPair();
        const jwk = await exportPublicKeyJWK(kp.publicKey);
        const imported = await importPublicKeyJWK(jwk);

        expect(imported.type).toBe('public');
        expect(imported.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
        expect(imported.usages).toContain('verify');
    });

    it('imported key can verify signatures from original private key', async () => {
        const kp = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('test payload');

        // Sign with original private key
        const sig = new Uint8Array(
            await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data)
        );

        // Export and re-import the public key
        const jwk = await exportPublicKeyJWK(kp.publicKey);
        const imported = await importPublicKeyJWK(jwk);

        // Verify with imported key
        const valid = await verifySignature(imported, data, sig);
        expect(valid).toBe(true);
    });
});

describe('importPublicKeyJWK error paths', () => {
    it('rejects invalid JWK (missing fields)', async () => {
        await expect(importPublicKeyJWK({ kty: 'EC' })).rejects.toThrow();
    });

    it('rejects JWK with wrong curve', async () => {
        // Create a valid P-256 JWK then corrupt the curve
        const kp = await generateEphemeralKeyPair();
        const jwk = await exportPublicKeyJWK(kp.publicKey);
        jwk.crv = 'P-384';
        // Should reject because algorithm specifies P-256 but JWK says P-384
        await expect(importPublicKeyJWK(jwk)).rejects.toThrow();
    });
});

describe('verifySignature', () => {
    it('returns true for valid ECDSA-SHA256 signature', async () => {
        const kp = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('hello miTch');
        const sig = new Uint8Array(
            await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data)
        );
        const result = await verifySignature(kp.publicKey, data, sig);
        expect(result).toBe(true);
    });

    it('returns false for tampered data', async () => {
        const kp = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('original');
        const sig = new Uint8Array(
            await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data)
        );
        const tampered = new TextEncoder().encode('tampered');
        const result = await verifySignature(kp.publicKey, tampered, sig);
        expect(result).toBe(false);
    });

    it('returns false for tampered signature', async () => {
        const kp = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('payload');
        const sig = new Uint8Array(
            await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data)
        );
        // Flip a byte in the signature
        sig[0] ^= 0xff;
        const result = await verifySignature(kp.publicKey, data, sig);
        expect(result).toBe(false);
    });

    it('returns false for wrong key', async () => {
        const kp1 = await generateEphemeralKeyPair();
        const kp2 = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('test');
        const sig = new Uint8Array(
            await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp1.privateKey, data)
        );
        const result = await verifySignature(kp2.publicKey, data, sig);
        expect(result).toBe(false);
    });

    it('returns false for empty signature (does not throw)', async () => {
        const kp = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('test');
        const result = await verifySignature(kp.publicKey, data, new Uint8Array(0));
        expect(result).toBe(false);
    });

    it('returns false for empty data with valid-length garbage sig', async () => {
        const kp = await generateEphemeralKeyPair();
        const garbageSig = new Uint8Array(64);
        crypto.getRandomValues(garbageSig);
        const result = await verifySignature(kp.publicKey, new Uint8Array(0), garbageSig);
        expect(result).toBe(false);
    });
});

describe('sha256', () => {
    it('hashes a string to 64-char hex', async () => {
        const hash = await sha256('hello');
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('produces known hash for empty string', async () => {
        const hash = await sha256('');
        // SHA-256 of empty string is well-known
        expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('produces deterministic output', async () => {
        const h1 = await sha256('deterministic');
        const h2 = await sha256('deterministic');
        expect(h1).toBe(h2);
    });

    it('produces different hashes for different input', async () => {
        const h1 = await sha256('input-a');
        const h2 = await sha256('input-b');
        expect(h1).not.toBe(h2);
    });

    it('accepts Uint8Array input', async () => {
        const data = new TextEncoder().encode('binary data');
        const hash = await sha256(data);
        expect(hash).toHaveLength(64);
        // Should match the string version
        const hashStr = await sha256('binary data');
        expect(hash).toBe(hashStr);
    });
});

describe('decryptJWE', () => {
    it('throws error for invalid JWE', async () => {
        const kp = await generateEphemeralKeyPair();
        await expect(decryptJWE('some.jwe.token', kp.privateKey)).rejects.toThrow(
            'JWE_DECRYPT_FAILED'
        );
    });
});

describe('base64UrlToBuffer / bufferToBase64Url roundtrip', () => {
    it('round-trips arbitrary bytes', () => {
        const original = new Uint8Array([0, 1, 2, 255, 128, 64, 32]);
        const encoded = bufferToBase64Url(original);
        const decoded = base64UrlToBuffer(encoded);
        expect(decoded).toEqual(original);
    });

    it('encodes to URL-safe characters (no +, /, =)', () => {
        const data = new Uint8Array(32);
        crypto.getRandomValues(data);
        const encoded = bufferToBase64Url(data);
        expect(encoded).not.toContain('+');
        expect(encoded).not.toContain('/');
        expect(encoded).not.toContain('=');
    });

    it('handles empty buffer', () => {
        const encoded = bufferToBase64Url(new Uint8Array(0));
        expect(encoded).toBe('');
        const decoded = base64UrlToBuffer(encoded);
        expect(decoded).toEqual(new Uint8Array(0));
    });

    it('handles single byte', () => {
        const original = new Uint8Array([42]);
        const encoded = bufferToBase64Url(original);
        const decoded = base64UrlToBuffer(encoded);
        expect(decoded).toEqual(original);
    });

    it('handles base64url with padding-requiring lengths', () => {
        // 1 byte = 2 base64 chars + 2 padding (removed in url-safe)
        // 2 bytes = 3 base64 chars + 1 padding
        // 3 bytes = 4 base64 chars + 0 padding
        for (const len of [1, 2, 3, 4, 5, 16, 31, 32, 33]) {
            const original = new Uint8Array(len);
            crypto.getRandomValues(original);
            const encoded = bufferToBase64Url(original);
            const decoded = base64UrlToBuffer(encoded);
            expect(decoded).toEqual(original);
        }
    });
});
