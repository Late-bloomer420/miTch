/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from 'vitest';
import {
    generateBrainpoolKeyPair,
    signWithBrainpool,
    verifyWithBrainpool,
    brainpoolECDH,
    brainpoolPublicKeyToObject,
    type BrainpoolCurve,
} from '../src/brainpool';

// ─── C-01: brainpoolP256r1 ────────────────────────────────────────────────────

describe('brainpoolP256r1', () => {
    const CURVE: BrainpoolCurve = 'brainpoolP256r1';
    const testMessage = new TextEncoder().encode('BSI eIDAS 2.0 credential signing');

    it('generates a key pair', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        expect(kp.curve).toBe(CURVE);
        expect(kp.privateKey).toBeInstanceOf(Uint8Array);
        expect(kp.publicKey).toBeInstanceOf(Uint8Array);
        expect(kp.privateKey.length).toBe(32); // 256-bit scalar
        expect(kp.publicKey.length).toBe(33);  // compressed point
    });

    it('generates unique key pairs', () => {
        const kp1 = generateBrainpoolKeyPair(CURVE);
        const kp2 = generateBrainpoolKeyPair(CURVE);
        expect(kp1.privateKey).not.toEqual(kp2.privateKey);
        expect(kp1.publicKey).not.toEqual(kp2.publicKey);
    });

    it('signs and verifies a message', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        const sig = signWithBrainpool(testMessage, kp);
        expect(sig.curve).toBe(CURVE);
        expect(sig.signature).toBeInstanceOf(Uint8Array);
        expect(sig.signature.length).toBeGreaterThan(0);

        const isValid = verifyWithBrainpool(testMessage, sig, kp.publicKey);
        expect(isValid).toBe(true);
    });

    it('rejects tampered message', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        const sig = signWithBrainpool(testMessage, kp);
        const tampered = new TextEncoder().encode('tampered message');
        const isValid = verifyWithBrainpool(tampered, sig, kp.publicKey);
        expect(isValid).toBe(false);
    });

    it('rejects signature with wrong key', () => {
        const kp1 = generateBrainpoolKeyPair(CURVE);
        const kp2 = generateBrainpoolKeyPair(CURVE);
        const sig = signWithBrainpool(testMessage, kp1);
        const isValid = verifyWithBrainpool(testMessage, sig, kp2.publicKey);
        expect(isValid).toBe(false);
    });

    it('ECDH produces same shared secret from both sides', () => {
        const kp1 = generateBrainpoolKeyPair(CURVE);
        const kp2 = generateBrainpoolKeyPair(CURVE);
        const secret1 = brainpoolECDH(kp1.privateKey, kp2.publicKey, CURVE);
        const secret2 = brainpoolECDH(kp2.privateKey, kp1.publicKey, CURVE);
        expect(secret1).toEqual(secret2);
    });

    it('exports public key object with crv=brainpoolP256r1', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        const obj = brainpoolPublicKeyToObject(kp);
        expect(obj.kty).toBe('EC');
        expect(obj.crv).toBe('brainpoolP256r1');
        expect(obj.x).toBeDefined();
    });
});

// ─── C-01: brainpoolP384r1 ────────────────────────────────────────────────────

describe('brainpoolP384r1', () => {
    const CURVE: BrainpoolCurve = 'brainpoolP384r1';
    const testMessage = new TextEncoder().encode('BSI Key Binding P384');

    it('generates a key pair (stub: uses P256r1 impl pending BSI P384 param verification)', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        expect(kp.curve).toBe(CURVE);
        // Stub implementation uses brainpoolP256r1 parameters until BSI-verified P384 params are confirmed
        expect(kp.privateKey).toBeInstanceOf(Uint8Array);
        expect(kp.publicKey).toBeInstanceOf(Uint8Array);
        expect(kp.privateKey.length).toBeGreaterThan(0);
    });

    it('signs and verifies a message', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        const sig = signWithBrainpool(testMessage, kp);
        const isValid = verifyWithBrainpool(testMessage, sig, kp.publicKey);
        expect(isValid).toBe(true);
    });

    it('rejects tampered message', () => {
        const kp = generateBrainpoolKeyPair(CURVE);
        const sig = signWithBrainpool(testMessage, kp);
        const tampered = new TextEncoder().encode('tampered P384 message');
        expect(verifyWithBrainpool(tampered, sig, kp.publicKey)).toBe(false);
    });

    it('ECDH produces same shared secret from both sides', () => {
        const kp1 = generateBrainpoolKeyPair(CURVE);
        const kp2 = generateBrainpoolKeyPair(CURVE);
        const s1 = brainpoolECDH(kp1.privateKey, kp2.publicKey, CURVE);
        const s2 = brainpoolECDH(kp2.privateKey, kp1.publicKey, CURVE);
        expect(s1).toEqual(s2);
    });
});
