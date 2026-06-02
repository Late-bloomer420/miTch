import { describe, it, expect } from 'vitest';
import { mlDSA65, mlKEM768, slhDSASHA2128s, resolvePQCSigner, resolvePQCKEM } from '../src/index';

describe('ML-DSA-65 (Diligence)', { timeout: 60_000 }, () => {
    it('keygen returns correct key sizes', () => {
        const kp = mlDSA65.keygen();
        expect(kp.publicKey.length).toBe(1952);
        expect(kp.secretKey.length).toBe(4032);
    });

    it('sign produces a signature of correct length', () => {
        const msg = new TextEncoder().encode('test message');
        const kp = mlDSA65.keygen();
        const sig = mlDSA65.sign(kp.secretKey, msg);
        expect(sig.length).toBe(3309);
    });

    it('verify accepts valid signature', () => {
        const msg = new TextEncoder().encode('test message');
        const kp = mlDSA65.keygen();
        const sig = mlDSA65.sign(kp.secretKey, msg);
        const isValid = mlDSA65.verify(kp.publicKey, msg, sig);
        expect(isValid).toBe(true);
    });

    it('verify rejects wrong public key', () => {
        const msg = new TextEncoder().encode('test message');
        const kp1 = mlDSA65.keygen();
        const kp2 = mlDSA65.keygen();
        const sig = mlDSA65.sign(kp1.secretKey, msg);
        const isValid = mlDSA65.verify(kp2.publicKey, msg, sig);
        expect(isValid).toBe(false);
    });

    it('verify rejects tampered message', () => {
        const msg = new TextEncoder().encode('test message');
        const kp = mlDSA65.keygen();
        const sig = mlDSA65.sign(kp.secretKey, msg);
        const isValid = mlDSA65.verify(kp.publicKey, new TextEncoder().encode('tampered'), sig);
        expect(isValid).toBe(false);
    });
});

describe('ML-KEM-768 (Kyber)', { timeout: 60_000 }, () => {
    it('keygen produces valid keys', () => {
        const kp = mlKEM768.keygen();
        expect(kp.publicKey.length).toBe(1184);
        expect(kp.secretKey.length).toBe(2400);
    });

    it('encapsulate/decapsulate produces matching shared secrets', () => {
        const kp = mlKEM768.keygen();
        const { cipherText, sharedSecret: ss1 } = mlKEM768.encapsulate(kp.publicKey);
        const ss2 = mlKEM768.decapsulate(cipherText, kp.secretKey);
        expect(ss1).toEqual(ss2);
    });

    it('cipherText has correct length', () => {
        const kp = mlKEM768.keygen();
        const { cipherText } = mlKEM768.encapsulate(kp.publicKey);
        expect(cipherText.length).toBe(1088);
    });
});

describe('SLH-DSA-SHA2-128s', { timeout: 120_000 }, () => {
    it('round-trip sign/verify', () => {
        const msg = new TextEncoder().encode('SPHINCS+ hash-based test message');
        const kp = slhDSASHA2128s.keygen();
        const sig = slhDSASHA2128s.sign(kp.secretKey, msg);
        expect(sig.length).toBeGreaterThan(0);
        expect(slhDSASHA2128s.verify(kp.publicKey, msg, sig)).toBe(true);
    });

    it('rejects tampered signature', () => {
        const msg = new TextEncoder().encode('tamper test');
        const kp = slhDSASHA2128s.keygen();
        const sig = slhDSASHA2128s.sign(kp.secretKey, msg);
        sig[0] ^= 0xFF; // flip one byte
        expect(slhDSASHA2128s.verify(kp.publicKey, msg, sig)).toBe(false);
    });
});

describe('Algorithm Registry', () => {
    it('resolves known algorithm IDs', () => {
        expect(resolvePQCSigner('ML-DSA-65')).toBeDefined();
        expect(resolvePQCKEM('ML-KEM-768')).toBeDefined();
    });

    it('returns null for unknown', () => {
        expect(resolvePQCSigner('ROT13' as any)).toBeNull();
    });
});
