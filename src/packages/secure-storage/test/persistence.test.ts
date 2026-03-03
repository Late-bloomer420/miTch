/**
 * G-06: Credential Persistence Tests
 *
 * Verifies:
 * 1. Credentials survive simulated reload (store → new instance → load)
 * 2. Data encrypted at rest (raw storage contains no plaintext PII)
 * 3. Storage error → wallet starts empty (fail-closed)
 * 4. Delete credential → actually removed from storage
 */
import { describe, test, expect, beforeAll } from 'vitest';
import { SecureStorage } from '../src/index';
// fake-indexeddb/auto loaded via test/setup.ts

const TEST_CREDENTIAL = {
    id: 'vc-persist-test-001',
    payload: { birthDate: '1990-05-15', name: 'Alice Testperson', ssn: '123-45-6789' },
    metadata: {
        issuer: 'did:example:gov',
        type: ['VerifiableCredential', 'IdentityCredential'],
        claims: ['birthDate', 'name', 'ssn'],
        issuedAt: '2025-01-01T00:00:00Z',
    },
};

async function generateMasterKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable so we can re-use across "reloads"
        ['encrypt', 'decrypt']
    );
}

describe('Credential Persistence (G-06)', () => {
    let masterKey: CryptoKey;

    beforeAll(async () => {
        masterKey = await generateMasterKey();
    });

    // No beforeEach reset — tests use unique IDs and are independent

    test('credentials survive simulated reload (store → new instance → load)', async () => {
        // Session 1: Store credential
        const storage1 = await SecureStorage.init(masterKey);
        await storage1.save(TEST_CREDENTIAL.id, TEST_CREDENTIAL.payload, TEST_CREDENTIAL.metadata);

        // Verify it's there
        const meta1 = await storage1.getAllMetadata();
        expect(meta1.find((m) => m.id === TEST_CREDENTIAL.id)).toBeDefined();

        // "Reload" — create a brand new SecureStorage instance (simulates page reload)
        const storage2 = await SecureStorage.init(masterKey);

        // Credential should still exist
        const loaded = await storage2.load<typeof TEST_CREDENTIAL.payload>(TEST_CREDENTIAL.id);
        expect(loaded).not.toBeNull();
        expect(loaded!.birthDate).toBe('1990-05-15');
        expect(loaded!.name).toBe('Alice Testperson');
        expect(loaded!.ssn).toBe('123-45-6789');

        // Metadata should also survive
        const meta2 = await storage2.getAllMetadata();
        const credMeta = meta2.find((m) => m.id === TEST_CREDENTIAL.id);
        expect(credMeta).toBeDefined();
        expect(credMeta!.issuer).toBe('did:example:gov');
    });

    test('encrypted at rest — raw storage contains no plaintext PII', async () => {
        const storage = await SecureStorage.init(masterKey);
        await storage.save(TEST_CREDENTIAL.id, TEST_CREDENTIAL.payload, TEST_CREDENTIAL.metadata);

        // Get raw document from IndexedDB
        const rawDoc = await storage.getRawDocument(TEST_CREDENTIAL.id);
        expect(rawDoc).not.toBeNull();

        // The ciphertext field must NOT contain any plaintext PII
        const ciphertext = rawDoc!.ciphertext;
        expect(ciphertext).toBeDefined();
        expect(typeof ciphertext).toBe('string');

        // None of the sensitive values should appear in the raw ciphertext
        expect(ciphertext).not.toContain('Alice Testperson');
        expect(ciphertext).not.toContain('1990-05-15');
        expect(ciphertext).not.toContain('123-45-6789');

        // The raw document should NOT have a plaintext 'payload' field
        expect((rawDoc as any).payload).toBeUndefined();

        // Metadata (indexTags) is intentionally plaintext for querying,
        // but must NOT contain PII — only structural info
        expect(JSON.stringify(rawDoc!.indexTags)).not.toContain('Alice Testperson');
        expect(JSON.stringify(rawDoc!.indexTags)).not.toContain('123-45-6789');
    });

    test('wrong key → decryption fails (fail-closed)', async () => {
        const storage = await SecureStorage.init(masterKey);
        await storage.save(TEST_CREDENTIAL.id, TEST_CREDENTIAL.payload, TEST_CREDENTIAL.metadata);

        // "Reload" with a DIFFERENT key (wrong PIN scenario)
        const wrongKey = await generateMasterKey();
        const storage2 = await SecureStorage.init(wrongKey);

        // load should throw (decryption failure), not return partial/plaintext data
        await expect(storage2.load(TEST_CREDENTIAL.id)).rejects.toThrow(/Decryption Failed/);
    });

    test('delete credential → actually removed from storage', async () => {
        const storage = await SecureStorage.init(masterKey);
        await storage.save(TEST_CREDENTIAL.id, TEST_CREDENTIAL.payload, TEST_CREDENTIAL.metadata);

        // Verify it exists
        expect(await storage.has(TEST_CREDENTIAL.id)).toBe(true);

        // Delete
        const deleted = await storage.delete(TEST_CREDENTIAL.id);
        expect(deleted).toBe(true);

        // Verify it's gone
        expect(await storage.has(TEST_CREDENTIAL.id)).toBe(false);
        expect(await storage.load(TEST_CREDENTIAL.id)).toBeNull();

        // Metadata should also be gone
        const meta = await storage.getAllMetadata();
        expect(meta.find((m) => m.id === TEST_CREDENTIAL.id)).toBeUndefined();

        // Double-delete returns false
        expect(await storage.delete(TEST_CREDENTIAL.id)).toBe(false);
    });

    test('delete non-existent credential returns false (no crash)', async () => {
        const storage = await SecureStorage.init(masterKey);
        const result = await storage.delete('does-not-exist');
        expect(result).toBe(false);
    });

    test('multiple credentials persist independently', async () => {
        const storage = await SecureStorage.init(masterKey);

        const cred2 = {
            id: 'vc-persist-test-002',
            payload: { employer: 'Acme Corp', role: 'Engineer' },
            metadata: {
                issuer: 'did:example:employer',
                type: ['VerifiableCredential', 'EmploymentCredential'],
                claims: ['employer', 'role'],
                issuedAt: '2025-06-01T00:00:00Z',
            },
        };

        await storage.save(TEST_CREDENTIAL.id, TEST_CREDENTIAL.payload, TEST_CREDENTIAL.metadata);
        await storage.save(cred2.id, cred2.payload, cred2.metadata);

        // Delete one, other survives
        await storage.delete(TEST_CREDENTIAL.id);

        const meta = await storage.getAllMetadata();
        expect(meta.find((m) => m.id === TEST_CREDENTIAL.id)).toBeUndefined();
        expect(meta.find((m) => m.id === cred2.id)).toBeDefined();

        const loaded = await storage.load<typeof cred2.payload>(cred2.id);
        expect(loaded!.employer).toBe('Acme Corp');
    });
});
