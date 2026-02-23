
import { describe, test, expect, beforeAll } from 'vitest';
import { SecureStorage } from '../src/index';
import type { StoredCredentialMetadata } from '@mitch/shared-types';

// Simple IndexedDB Mock for Node Environment (if not using jsdom)
// This is a minimal implementation to make the tests pass in a raw Node environment.
// In a real setup, we should use 'fake-indexeddb' or 'vitest-environment-jsdom'.
if (typeof indexedDB === 'undefined') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (global as any).indexedDB = require('fake-indexeddb');
    // If fake-indexeddb is not installed, this will fail. 
    // We should rely on the environment being set up correctly or mock it manually.
    // For this PoC, let's assume the user runs with an environment that supports it.
}

describe('SecureStorage', () => {
    let storage: SecureStorage;
    let masterKey: CryptoKey;

    beforeAll(async () => {
        // Generate a real key using WebCrypto (available in Node 15+)
        masterKey = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );

        storage = await SecureStorage.init(masterKey);
    });

    test('save and load a credential', async () => {
        const id = 'cred-test-1';
        const secretData = { sensitive: 'my-secret-birthdate' };
        const metadata: Omit<StoredCredentialMetadata, 'id'> = {
            issuer: 'did:example:issuer',
            type: ['AgeCredential'],
            claims: ['isOver18'],
            issuedAt: new Date().toISOString()
        };

        await storage.save(id, secretData, metadata);

        // Load back
        const loaded = await storage.load<{ sensitive: string }>(id);
        expect(loaded).toBeDefined();
        expect(loaded?.sensitive).toBe('my-secret-birthdate');
    });

    test('getAllMetadata should return plain tags', async () => {
        const list = await storage.getAllMetadata();
        expect(list.length).toBeGreaterThan(0);
        const item = list.find(x => x.id === 'cred-test-1');
        expect(item).toBeDefined();
        expect(item?.issuer).toBe('did:example:issuer');
        // valid check implies we didn't get the cipher text back, just the metadata
        expect((item as any).ciphertext).toBeUndefined();
    });

    test('load non-existent returns null', async () => {
        const loaded = await storage.load('non-existent');
        expect(loaded).toBeNull();
    });
});
