import { describe, test, expect } from 'vitest';
import { generateKeyPair, generateSymmetricKey, deriveKeyFromPassword } from '../src/keys';

describe('Key Generation', () => {
    test('ECDSA key pair generation', async () => {
        const { publicKey, privateKey } = await generateKeyPair();
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
        // Public keys are extractable
        expect(publicKey.extractable).toBe(true);
        // Private keys are non-extractable
        expect(privateKey.extractable).toBe(false);
    });

    test('Symmetric AES‑GCM key generation', async () => {
        const key = await generateSymmetricKey();
        expect(key).toBeDefined();
        expect(key.type).toBe('secret');
        expect(key.algorithm.name).toBe('AES-GCM');
    });

    test('Derive key from password (PBKDF2)', async () => {
        const password = 'strong‑password';
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await deriveKeyFromPassword(password, salt);
        expect(key).toBeDefined();
        expect(key.type).toBe('secret');
        expect(key.algorithm.name).toBe('AES-GCM');
    });
});
