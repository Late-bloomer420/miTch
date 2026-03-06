import { describe, it, expect } from 'vitest';
import { EphemeralKeyManager } from '../audit/cryptoShred';

describe('EphemeralKeyManager', () => {
    it('creates a new key with unique keyId', () => {
        const mgr = new EphemeralKeyManager();
        const k1 = mgr.createKey();
        const k2 = mgr.createKey();
        expect(k1.keyId).not.toBe(k2.keyId);
        expect(k1.destroyed).toBe(false);
        expect(k1.algorithm).toBe('aes-256-cbc');
    });

    it('encrypts and decrypts round-trip', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        const plaintext = 'sensitive user data: age=27, name=Alice';
        const encrypted = mgr.encrypt(key.keyId, plaintext);
        expect(encrypted.ciphertext).not.toBe(plaintext);
        const decrypted = mgr.decrypt(encrypted);
        expect(decrypted).toBe(plaintext);
    });

    it('ciphertext is hex-encoded', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        const enc = mgr.encrypt(key.keyId, 'test');
        expect(/^[0-9a-f]+$/.test(enc.ciphertext)).toBe(true);
    });

    it('shred returns proof with correct fields', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        const proof = mgr.shred(key.keyId);
        expect(proof.keyId).toBe(key.keyId);
        expect(proof.method).toBe('key_zeroed');
        expect(proof.algorithm).toBe('aes-256-cbc');
        expect(proof.destroyedAt).toMatch(/^\d{4}-/);
    });

    it('after shred, key is destroyed', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        mgr.shred(key.keyId);
        expect(mgr.isDestroyed(key.keyId)).toBe(true);
        expect(mgr.isActive(key.keyId)).toBe(false);
    });

    it('decrypt after shred throws key_destroyed', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        const encrypted = mgr.encrypt(key.keyId, 'secret');
        mgr.shred(key.keyId);
        expect(() => mgr.decrypt(encrypted)).toThrow('key_destroyed_data_irrecoverable');
    });

    it('encrypt after shred throws key_destroyed', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        mgr.shred(key.keyId);
        expect(() => mgr.encrypt(key.keyId, 'data')).toThrow('key_destroyed');
    });

    it('double shred throws already_destroyed', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        mgr.shred(key.keyId);
        expect(() => mgr.shred(key.keyId)).toThrow('already_destroyed');
    });

    it('shred unknown key throws key_not_found', () => {
        const mgr = new EphemeralKeyManager();
        expect(() => mgr.shred('nonexistent-key')).toThrow('key_not_found');
    });

    it('key zeroing is effective (key buffer filled with zeros)', () => {
        const mgr = new EphemeralKeyManager();
        const key = mgr.createKey();
        // Keep reference to the buffer before shred
        const keyRef = key.key;
        mgr.shred(key.keyId);
        // After shred, the buffer should be zeroed
        expect(keyRef.every(b => b === 0)).toBe(true);
    });
});
