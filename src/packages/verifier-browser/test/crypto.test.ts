/**
 * verifier-browser/crypto.ts — WebCrypto utility tests
 *
 * Covers:
 * - generateEphemeralKeyPair: ECDSA P-256 key pair
 * - generateNonce: 32-byte hex nonce
 * - generateSessionId: UUID v4
 * - exportPublicKeyJWK / importPublicKeyJWK: JWK round-trip
 * - verifySignature: ECDSA-SHA256 sign + verify
 * - sha256: digest correctness
 * - base64UrlToBuffer / bufferToBase64Url: encoding round-trips
 * - decryptJWE: ECDH-ES + A256GCM full decrypt
 */

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
} from '../src/crypto.js';

// ─── generateEphemeralKeyPair ────────────────────────────────────────────────

describe('generateEphemeralKeyPair', () => {
    it('returns a CryptoKeyPair with privateKey and publicKey', async () => {
        const pair = await generateEphemeralKeyPair();
        expect(pair.privateKey).toBeDefined();
        expect(pair.publicKey).toBeDefined();
    });

    it('publicKey algorithm is ECDSA / P-256', async () => {
        const pair = await generateEphemeralKeyPair();
        expect(pair.publicKey.algorithm.name).toBe('ECDSA');
        expect((pair.publicKey.algorithm as EcKeyAlgorithm).namedCurve).toBe('P-256');
    });

    it('key is extractable (for JWK export)', async () => {
        const pair = await generateEphemeralKeyPair();
        expect(pair.privateKey.extractable).toBe(true);
        expect(pair.publicKey.extractable).toBe(true);
    });

    it('generates distinct key pairs on successive calls', async () => {
        const p1 = await generateEphemeralKeyPair();
        const p2 = await generateEphemeralKeyPair();
        const jwk1 = await crypto.subtle.exportKey('jwk', p1.publicKey);
        const jwk2 = await crypto.subtle.exportKey('jwk', p2.publicKey);
        expect(jwk1.x).not.toBe(jwk2.x);
    });

    it('private key supports sign, public key supports verify', async () => {
        const pair = await generateEphemeralKeyPair();
        expect(pair.privateKey.usages).toContain('sign');
        expect(pair.publicKey.usages).toContain('verify');
    });
});

// ─── generateNonce ───────────────────────────────────────────────────────────

describe('generateNonce', () => {
    it('returns a 64-character hex string (32 bytes)', () => {
        const nonce = generateNonce();
        expect(nonce).toHaveLength(64);
        expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    });

    it('generates unique nonces', () => {
        const nonces = new Set(Array.from({ length: 20 }, () => generateNonce()));
        expect(nonces.size).toBe(20);
    });
});

// ─── generateSessionId ───────────────────────────────────────────────────────

describe('generateSessionId', () => {
    it('returns a UUID v4 formatted string', () => {
        const id = generateSessionId();
        expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    it('generates unique session IDs', () => {
        const ids = new Set(Array.from({ length: 20 }, () => generateSessionId()));
        expect(ids.size).toBe(20);
    });
});

// ─── exportPublicKeyJWK / importPublicKeyJWK ─────────────────────────────────

describe('exportPublicKeyJWK / importPublicKeyJWK', () => {
    it('round-trips: export then import produces equivalent key', async () => {
        const pair = await generateEphemeralKeyPair();
        const jwk = await exportPublicKeyJWK(pair.publicKey);
        const imported = await importPublicKeyJWK(jwk);
        expect(imported.type).toBe('public');
        expect(imported.algorithm.name).toBe('ECDSA');
    });

    it('exported JWK has kty=EC, crv=P-256', async () => {
        const pair = await generateEphemeralKeyPair();
        const jwk = await exportPublicKeyJWK(pair.publicKey);
        expect(jwk.kty).toBe('EC');
        expect(jwk.crv).toBe('P-256');
        expect(jwk.x).toBeTruthy();
        expect(jwk.y).toBeTruthy();
    });

    it('imported key can verify signature created with original private key', async () => {
        const pair = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('test message');
        const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data);

        const jwk = await exportPublicKeyJWK(pair.publicKey);
        const importedPub = await importPublicKeyJWK(jwk);

        const valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            importedPub,
            sig,
            data,
        );
        expect(valid).toBe(true);
    });

    it('imported key has verify usage', async () => {
        const pair = await generateEphemeralKeyPair();
        const jwk = await exportPublicKeyJWK(pair.publicKey);
        const imported = await importPublicKeyJWK(jwk);
        expect(imported.usages).toContain('verify');
    });
});

// ─── verifySignature ─────────────────────────────────────────────────────────

describe('verifySignature', () => {
    it('returns true for valid signature', async () => {
        const pair = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('hello');
        const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data);
        const result = await verifySignature(pair.publicKey, data, new Uint8Array(sig));
        expect(result).toBe(true);
    });

    it('returns false for tampered data', async () => {
        const pair = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('hello');
        const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data);
        const tampered = new TextEncoder().encode('HELLO'); // different data
        const result = await verifySignature(pair.publicKey, tampered, new Uint8Array(sig));
        expect(result).toBe(false);
    });

    it('returns false for tampered signature', async () => {
        const pair = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('hello');
        const sig = new Uint8Array(64).fill(0xff); // garbage signature
        const result = await verifySignature(pair.publicKey, data, sig);
        expect(result).toBe(false);
    });

    it('returns false for wrong key', async () => {
        const pair1 = await generateEphemeralKeyPair();
        const pair2 = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('hello');
        const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair1.privateKey, data);
        const result = await verifySignature(pair2.publicKey, data, new Uint8Array(sig));
        expect(result).toBe(false);
    });

    it('returns false for empty signature', async () => {
        const pair = await generateEphemeralKeyPair();
        const data = new TextEncoder().encode('hello');
        const result = await verifySignature(pair.publicKey, data, new Uint8Array(0));
        expect(result).toBe(false);
    });
});

// ─── sha256 ──────────────────────────────────────────────────────────────────

describe('sha256', () => {
    it('returns a 64-character hex string', async () => {
        const hash = await sha256('hello');
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('matches known SHA-256 value for empty string', async () => {
        const hash = await sha256('');
        // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb924' + '27ae41e4649b934ca495991b7852b855');
    });

    it('matches SHA-256("abc") output of Uint8Array and string inputs', async () => {
        // Cross-check: sha256('abc') and sha256(Uint8Array([97,98,99])) must match
        const fromString = await sha256('abc');
        const fromBytes = await sha256(new Uint8Array([97, 98, 99]));
        expect(fromString).toBe(fromBytes);
        expect(fromString).toHaveLength(64);
    });

    it('accepts Uint8Array input', async () => {
        const bytes = new TextEncoder().encode('abc');
        const hashFromBytes = await sha256(bytes);
        const hashFromString = await sha256('abc');
        expect(hashFromBytes).toBe(hashFromString);
    });

    it('same input always produces same hash (deterministic)', async () => {
        const h1 = await sha256('deterministic');
        const h2 = await sha256('deterministic');
        expect(h1).toBe(h2);
    });

    it('different inputs produce different hashes', async () => {
        const h1 = await sha256('foo');
        const h2 = await sha256('bar');
        expect(h1).not.toBe(h2);
    });
});

// ─── base64UrlToBuffer / bufferToBase64Url ───────────────────────────────────

describe('base64UrlToBuffer / bufferToBase64Url', () => {
    it('round-trips arbitrary bytes', () => {
        const original = new Uint8Array([0, 1, 2, 128, 255, 64, 32]);
        const encoded = bufferToBase64Url(original);
        const decoded = base64UrlToBuffer(encoded);
        expect(decoded).toEqual(original);
    });

    it('uses URL-safe alphabet (no +, /, =)', () => {
        const bytes = new Uint8Array(48).fill(0xfb); // will produce + and / in standard base64
        const encoded = bufferToBase64Url(bytes);
        expect(encoded).not.toContain('+');
        expect(encoded).not.toContain('/');
        expect(encoded).not.toContain('=');
    });

    it('round-trips empty buffer', () => {
        const empty = new Uint8Array(0);
        const encoded = bufferToBase64Url(empty);
        const decoded = base64UrlToBuffer(encoded);
        expect(decoded.length).toBe(0);
    });

    it('round-trips 32-byte random nonce', () => {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const encoded = bufferToBase64Url(nonce);
        const decoded = base64UrlToBuffer(encoded);
        expect(decoded).toEqual(nonce);
    });

    it('base64url decodes standard known value', () => {
        // "Man" in base64url = "TWFu"
        const decoded = base64UrlToBuffer('TWFu');
        expect(decoded[0]).toBe(77); // 'M'
        expect(decoded[1]).toBe(97); // 'a'
        expect(decoded[2]).toBe(110); // 'n'
    });
});

// ─── decryptJWE ──────────────────────────────────────────────────────────────

/**
 * Helper: build a compact JWE encrypted for a given ECDH P-256 public key,
 * using ECDH-ES + A256GCM (same as verifier-browser expects).
 */
async function buildJWE(plaintext: string, recipientPublicKey: CryptoKey): Promise<string> {
    // 1. Generate ephemeral ECDH key pair
    const ephemeral = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits'],
    );

    // 2. Export ephemeral public key as JWK (epk)
    const epkJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);

    // 3. Re-import recipient public key as ECDH
    const recipJwk = await crypto.subtle.exportKey('jwk', recipientPublicKey);
    const recipECDH = await crypto.subtle.importKey(
        'jwk',
        { ...recipJwk, key_ops: [] },
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        [],
    );

    // 4. ECDH deriveBits — Z
    const zBuf = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipECDH },
        ephemeral.privateKey,
        256,
    );
    const Z = new Uint8Array(zBuf);

    // 5. CONCAT-KDF (single iteration, SHA-256)
    const enc = new TextEncoder();
    function lp(d: Uint8Array): Uint8Array {
        const out = new Uint8Array(4 + d.length);
        new DataView(out.buffer).setUint32(0, d.length, false);
        out.set(d, 4);
        return out;
    }
    function u32be(n: number): Uint8Array {
        const b = new Uint8Array(4);
        new DataView(b.buffer).setUint32(0, n, false);
        return b;
    }
    const algBytes = enc.encode('A256GCM');
    const otherInfo = [lp(algBytes), lp(new Uint8Array(0)), lp(new Uint8Array(0)), u32be(256)];
    const parts = [u32be(1), Z, ...otherInfo];
    const total = parts.reduce((s, p) => s + p.length, 0);
    const input = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { input.set(p, off); off += p.length; }
    const hashBuf = await crypto.subtle.digest('SHA-256', input);
    const cek = new Uint8Array(hashBuf).slice(0, 32);

    // 6. Import CEK
    const aesKey = await crypto.subtle.importKey(
        'raw', cek.buffer as ArrayBuffer,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt'],
    );

    // 7. Build protected header and encode
    const header = JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM', epk: epkJwk });
    const encodedHeader = btoa(header).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // 8. Encrypt plaintext with AES-256-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = enc.encode(encodedHeader);
    const ptBytes = enc.encode(plaintext);

    const ctBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        ptBytes,
    );

    // Split ciphertext and tag (WebCrypto appends 16-byte tag)
    const ctWithTag = new Uint8Array(ctBuf);
    const ciphertext = ctWithTag.slice(0, -16);
    const tag = ctWithTag.slice(-16);

    function b64u(buf: Uint8Array): string {
        return btoa(String.fromCharCode(...buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    // Compact JWE: header . "" . iv . ciphertext . tag
    return [encodedHeader, '', b64u(iv), b64u(ciphertext), b64u(tag)].join('.');
}

describe('decryptJWE', () => {
    it('decrypts a valid JWE compact serialization', async () => {
        const pair = await generateEphemeralKeyPair();
        const plaintext = 'hello from JWE';
        const jwe = await buildJWE(plaintext, pair.publicKey);
        const decrypted = await decryptJWE(jwe, pair.privateKey);
        expect(decrypted).toBe(plaintext);
    });

    it('decrypts JSON payload correctly', async () => {
        const pair = await generateEphemeralKeyPair();
        const payload = JSON.stringify({ sub: 'user-1', age: 21, verified: true });
        const jwe = await buildJWE(payload, pair.publicKey);
        const decrypted = await decryptJWE(jwe, pair.privateKey);
        expect(JSON.parse(decrypted)).toEqual({ sub: 'user-1', age: 21, verified: true });
    });

    it('decrypts unicode payload', async () => {
        const pair = await generateEphemeralKeyPair();
        const payload = 'Ö𝄞🔑€ privacy';
        const jwe = await buildJWE(payload, pair.publicKey);
        const decrypted = await decryptJWE(jwe, pair.privateKey);
        expect(decrypted).toBe(payload);
    });

    it('throws JWE_DECRYPT_FAILED for wrong recipient key', async () => {
        const pair1 = await generateEphemeralKeyPair();
        const pair2 = await generateEphemeralKeyPair();
        const jwe = await buildJWE('secret', pair1.publicKey);
        await expect(decryptJWE(jwe, pair2.privateKey)).rejects.toThrow();
    });

    it('throws for malformed JWE (wrong number of parts)', async () => {
        await expect(decryptJWE('a.b.c.d', {} as CryptoKey)).rejects.toThrow('JWE_DECRYPT_FAILED');
    });

    it('throws for unsupported alg', async () => {
        // Build a valid JWE structure but swap alg
        const pair = await generateEphemeralKeyPair();
        const epkJwk = await exportPublicKeyJWK(pair.publicKey);
        const badHeader = btoa(JSON.stringify({ alg: 'RSA-OAEP', enc: 'A256GCM', epk: epkJwk }))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const jwe = `${badHeader}..AAAA.AAAA.AAAA`;
        await expect(decryptJWE(jwe, pair.privateKey)).rejects.toThrow('RSA-OAEP');
    });

    it('throws for unsupported enc', async () => {
        const pair = await generateEphemeralKeyPair();
        const epkJwk = await exportPublicKeyJWK(pair.publicKey);
        const badHeader = btoa(JSON.stringify({ alg: 'ECDH-ES', enc: 'A128GCM', epk: epkJwk }))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const jwe = `${badHeader}..AAAA.AAAA.AAAA`;
        await expect(decryptJWE(jwe, pair.privateKey)).rejects.toThrow('A128GCM');
    });

    it('throws for missing epk in header', async () => {
        const pair = await generateEphemeralKeyPair();
        const badHeader = btoa(JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const jwe = `${badHeader}..AAAA.AAAA.AAAA`;
        await expect(decryptJWE(jwe, pair.privateKey)).rejects.toThrow('epk');
    });

    it('different plaintexts produce different ciphertexts', async () => {
        const pair = await generateEphemeralKeyPair();
        const jwe1 = await buildJWE('message-A', pair.publicKey);
        const jwe2 = await buildJWE('message-B', pair.publicKey);
        expect(jwe1).not.toBe(jwe2);
    });
});
