/**
 * Spec 93 — Post-Quantum Cryptography (Live Implementation)
 *
 * Tests for @noble/post-quantum wrappers: ML-DSA, ML-KEM, SLH-DSA, Hybrid.
 */
import { describe, it, expect } from 'vitest';
import {
    mlDSA44, mlDSA65, mlDSA87,
    slhDSASHA2128s,
    mlKEM512, mlKEM768,
    hybridMLDSA44,
    resolvePQCSigner,
    resolvePQCKEM,
} from '../src/pqc.js';

// ─── ML-DSA signing ───────────────────────────────────────────────────────────

describe('ML-DSA-44', () => {
    const msg = new TextEncoder().encode('miTch PQC test — Guten Morgen');

    it('keygen returns correct key sizes', () => {
        const kp = mlDSA44.keygen();
        expect(kp.publicKey.length).toBe(mlDSA44.lengths.publicKey); // 1312
        expect(kp.secretKey.length).toBe(mlDSA44.lengths.secretKey); // 2560
    });

    it('sign produces a signature of correct length', () => {
        const kp = mlDSA44.keygen();
        const sig = mlDSA44.sign(kp.secretKey, msg);
        expect(sig.length).toBe(mlDSA44.lengths.signature); // 2420
    });

    it('verify accepts valid signature', () => {
        const kp = mlDSA44.keygen();
        const sig = mlDSA44.sign(kp.secretKey, msg);
        expect(mlDSA44.verify(kp.publicKey, msg, sig)).toBe(true);
    });

    it('verify rejects wrong public key', () => {
        const kp1 = mlDSA44.keygen();
        const kp2 = mlDSA44.keygen();
        const sig = mlDSA44.sign(kp1.secretKey, msg);
        expect(mlDSA44.verify(kp2.publicKey, msg, sig)).toBe(false);
    });

    it('verify rejects tampered message', () => {
        const kp = mlDSA44.keygen();
        const sig = mlDSA44.sign(kp.secretKey, msg);
        const tampered = new Uint8Array(msg);
        tampered[0] ^= 0xFF;
        expect(mlDSA44.verify(kp.publicKey, tampered, sig)).toBe(false);
    });

    it('deterministic with fixed seed', () => {
        const seed = new Uint8Array(32).fill(0xAB);
        const kp1 = mlDSA44.keygen(seed);
        const kp2 = mlDSA44.keygen(seed);
        expect(kp1.publicKey).toEqual(kp2.publicKey);
        expect(kp1.secretKey).toEqual(kp2.secretKey);
    });
});

describe('ML-DSA-65', () => {
    it('round-trip sign/verify', () => {
        const msg = new TextEncoder().encode('Level 3 test');
        const kp = mlDSA65.keygen();
        const sig = mlDSA65.sign(kp.secretKey, msg);
        expect(sig.length).toBe(mlDSA65.lengths.signature); // 3309
        expect(mlDSA65.verify(kp.publicKey, msg, sig)).toBe(true);
    });
});

describe('ML-DSA-87', () => {
    it('round-trip sign/verify', () => {
        const msg = new TextEncoder().encode('Level 5 test');
        const kp = mlDSA87.keygen();
        const sig = mlDSA87.sign(kp.secretKey, msg);
        expect(sig.length).toBe(mlDSA87.lengths.signature); // 4627
        expect(mlDSA87.verify(kp.publicKey, msg, sig)).toBe(true);
    });
});

// ─── SLH-DSA ─────────────────────────────────────────────────────────────────

describe('SLH-DSA-SHA2-128s', () => {
    it('round-trip sign/verify', () => {
        const msg = new TextEncoder().encode('SPHINCS+ hash-based test');
        const kp = slhDSASHA2128s.keygen();
        const sig = slhDSASHA2128s.sign(kp.secretKey, msg);
        expect(sig.length).toBeGreaterThan(0);
        expect(slhDSASHA2128s.verify(kp.publicKey, msg, sig)).toBe(true);
    });

    it('rejects tampered signature', () => {
        const msg = new TextEncoder().encode('tamper test');
        const kp = slhDSASHA2128s.keygen();
        const sig = slhDSASHA2128s.sign(kp.secretKey, msg);
        const bad = new Uint8Array(sig);
        bad[0] ^= 0xFF;
        expect(slhDSASHA2128s.verify(kp.publicKey, msg, bad)).toBe(false);
    });
});

// ─── ML-KEM ───────────────────────────────────────────────────────────────────

describe('ML-KEM-512', () => {
    it('encapsulate/decapsulate produces matching shared secrets', () => {
        const kp = mlKEM512.keygen();
        const { cipherText, sharedSecret: ssEnc } = mlKEM512.encapsulate(kp.publicKey);
        const ssDec = mlKEM512.decapsulate(cipherText, kp.secretKey);
        expect(ssEnc).toEqual(ssDec);
        expect(ssEnc.length).toBe(32);
    });

    it('cipherText has correct length', () => {
        const kp = mlKEM512.keygen();
        const { cipherText } = mlKEM512.encapsulate(kp.publicKey);
        expect(cipherText.length).toBe(mlKEM512.lengths.cipherText); // 768
    });

    it('different encapsulations produce different ciphertexts (probabilistic)', () => {
        const kp = mlKEM512.keygen();
        const r1 = mlKEM512.encapsulate(kp.publicKey);
        const r2 = mlKEM512.encapsulate(kp.publicKey);
        // With random seed, ciphertexts should differ almost surely
        expect(r1.cipherText).not.toEqual(r2.cipherText);
    });

    it('wrong secret key produces different shared secret', () => {
        const kp1 = mlKEM512.keygen();
        const kp2 = mlKEM512.keygen();
        const { cipherText, sharedSecret: ssEnc } = mlKEM512.encapsulate(kp1.publicKey);
        const ssWrong = mlKEM512.decapsulate(cipherText, kp2.secretKey);
        expect(ssWrong).not.toEqual(ssEnc);
    });
});

describe('ML-KEM-768', () => {
    it('encapsulate/decapsulate round-trip', () => {
        const kp = mlKEM768.keygen();
        const { cipherText, sharedSecret: ssEnc } = mlKEM768.encapsulate(kp.publicKey);
        const ssDec = mlKEM768.decapsulate(cipherText, kp.secretKey);
        expect(ssEnc).toEqual(ssDec);
        expect(cipherText.length).toBe(mlKEM768.lengths.cipherText); // 1088
    });
});

// ─── Hybrid ES256 + ML-DSA-44 ────────────────────────────────────────────────

describe('hybridMLDSA44', () => {
    const msg = new TextEncoder().encode('Hybrid quantum-safe signing test');

    it('keygen produces both classical and PQC keys', async () => {
        const kp = await hybridMLDSA44.keygen();
        expect(kp.publicKey.ecdsa).toBeInstanceOf(CryptoKey);
        expect(kp.secretKey.ecdsa).toBeInstanceOf(CryptoKey);
        expect(kp.publicKey.pqc.length).toBe(mlDSA44.lengths.publicKey);
        expect(kp.secretKey.pqc.length).toBe(mlDSA44.lengths.secretKey);
    });

    it('sign/verify round-trip passes', async () => {
        const kp = await hybridMLDSA44.keygen();
        const sig = await hybridMLDSA44.sign(kp.secretKey, msg);
        expect(await hybridMLDSA44.verify(kp.publicKey, msg, sig)).toBe(true);
    });

    it('composite signature contains both parts (>64 + 2420 bytes + 8 prefix bytes)', async () => {
        const kp = await hybridMLDSA44.keygen();
        const sig = await hybridMLDSA44.sign(kp.secretKey, msg);
        // 4 + 64 (ECDSA raw r||s) + 4 + 2420 (ML-DSA-44) = 2492
        expect(sig.length).toBe(4 + 64 + 4 + mlDSA44.lengths.signature);
    });

    it('rejects wrong PQC key (fail-closed)', async () => {
        const kp1 = await hybridMLDSA44.keygen();
        const kp2 = await hybridMLDSA44.keygen();
        const sig = await hybridMLDSA44.sign(kp1.secretKey, msg);
        // Use kp1 ECDSA pubkey but kp2 PQC pubkey → should fail
        const mixedPub = { ecdsa: kp1.publicKey.ecdsa, pqc: kp2.publicKey.pqc };
        expect(await hybridMLDSA44.verify(mixedPub, msg, sig)).toBe(false);
    });

    it('rejects wrong classical key (fail-closed)', async () => {
        const kp1 = await hybridMLDSA44.keygen();
        const kp2 = await hybridMLDSA44.keygen();
        const sig = await hybridMLDSA44.sign(kp1.secretKey, msg);
        // Use kp2 ECDSA pubkey but kp1 PQC pubkey → classical check should fail
        const mixedPub = { ecdsa: kp2.publicKey.ecdsa, pqc: kp1.publicKey.pqc };
        expect(await hybridMLDSA44.verify(mixedPub, msg, sig)).toBe(false);
    });

    it('rejects tampered message', async () => {
        const kp = await hybridMLDSA44.keygen();
        const sig = await hybridMLDSA44.sign(kp.secretKey, msg);
        const bad = new Uint8Array(msg);
        bad[0] ^= 0xFF;
        expect(await hybridMLDSA44.verify(kp.publicKey, bad, sig)).toBe(false);
    });
});

// ─── Registry resolvers ───────────────────────────────────────────────────────

describe('resolvePQCSigner', () => {
    it('resolves known algorithm IDs', () => {
        expect(resolvePQCSigner('ML-DSA-44')).toBe(mlDSA44);
        expect(resolvePQCSigner('ML-DSA-65')).toBe(mlDSA65);
        expect(resolvePQCSigner('ML-DSA-87')).toBe(mlDSA87);
        expect(resolvePQCSigner('SLH-DSA-SHA2-128s')).toBe(slhDSASHA2128s);
    });

    it('returns null for classical algorithms', () => {
        expect(resolvePQCSigner('ES256')).toBeNull();
        expect(resolvePQCSigner('RS256')).toBeNull();
    });
});

describe('resolvePQCKEM', () => {
    it('resolves known KEM IDs', () => {
        expect(resolvePQCKEM('ML-KEM-512')).toBe(mlKEM512);
        expect(resolvePQCKEM('ML-KEM-768')).toBe(mlKEM768);
    });

    it('returns null for unknown', () => {
        expect(resolvePQCKEM('ECDH-ES')).toBeNull();
    });
});
