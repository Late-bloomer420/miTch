import { describe, test, expect } from 'vitest';
import { generateSymmetricKey } from '../src/keys';
import { encrypt, decrypt } from '../src/encryption';

describe('AES-GCM Encryption', () => {
    test('encrypt and decrypt round‑trip', async () => {
        const key = await generateSymmetricKey();
        const plaintext = 'Hello miTch World';
        const ciphertext = await encrypt(plaintext, key);
        expect(ciphertext).not.toBe(plaintext);
        const recovered = await decrypt(ciphertext, key);
        expect(recovered).toBe(plaintext);
    });
});
