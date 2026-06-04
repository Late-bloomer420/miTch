/**
 * @module @mitch/secure-storage
 *
 * Secure Storage Module for Verifiable Credentials
 *
 * Provides encrypted storage for sensitive credential data.
 * All data is encrypted at rest using AES-256-GCM with a Master Key.
 *
 * ## Architecture
 * - Pluggable backends via IStorageAdapter (IndexedDB, Memory, etc.)
 * - T-36a: Supports selective claim decryption for data minimization
 */

import { encrypt, decrypt } from '@askmi/shared-crypto';
import type { StoredCredentialMetadata } from '@askmi/shared-types';
import type { IStorageAdapter, EncryptedDocument } from './IStorageAdapter';
import { BrowserIndexedDBAdapter } from './BrowserIndexedDBAdapter';

export * from './IStorageAdapter';
export * from './BrowserIndexedDBAdapter';
export * from './InMemoryStorageAdapter';

/**
 * Secure Storage for Verifiable Credentials.
 *
 * All credentials are encrypted before storage and can only be
 * decrypted with the correct Master Key. Implements data minimization
 * through selective claim decryption (T-36a).
 */
export class SecureStorage {
    private adapter: IStorageAdapter;
    private key: CryptoKey;

    private constructor(key: CryptoKey, adapter: IStorageAdapter) {
        this.key = key;
        this.adapter = adapter;
    }

    /**
     * Initialize the storage with a Master Key and optional adapter.
     * Defaults to BrowserIndexedDBAdapter.
     */
    static async init(masterKey: CryptoKey, adapter?: IStorageAdapter): Promise<SecureStorage> {
        const storageAdapter = adapter ?? new BrowserIndexedDBAdapter();
        return new SecureStorage(masterKey, storageAdapter);
    }

    /**
     * Reset the default storage.
     */
    static async reset(): Promise<void> {
        const adapter = new BrowserIndexedDBAdapter();
        await adapter.clear();
    }

    /**
     * Save a document (VC) securely.
     */
    async save(id: string, data: unknown, metadata: Omit<StoredCredentialMetadata, 'id'>): Promise<void> {
        const plaintext = JSON.stringify(data);
        const ciphertext = await encrypt(plaintext, this.key);

        const entry: EncryptedDocument = {
            id,
            ciphertext,
            indexTags: { ...metadata, id }
        };

        await this.adapter.save(entry);
    }

    /**
     * Retrieve and decrypt a document.
     */
    async load<T>(id: string): Promise<T | null> {
        const result = await this.adapter.load(id);
        if (!result) return null;

        try {
            const plaintext = await decrypt(result.ciphertext, this.key);
            return JSON.parse(plaintext) as T;
        } catch {
            throw new Error('Decryption Failed: Key might be wrong or data corrupted.');
        }
    }

    /**
     * T-36a: Claim-Level Selective Decryption
     */
    async loadSelectiveClaims<T extends Record<string, unknown>>(
        id: string,
        effectiveClaims: string[]
    ): Promise<Pick<T, string> | null> {
        const result = await this.adapter.load(id);
        if (!result) return null;

        try {
            const plaintext = await decrypt(result.ciphertext, this.key);
            const fullPayload = JSON.parse(plaintext) as T;

            const minimizedPayload: Record<string, unknown> = {};
            for (const claim of effectiveClaims) {
                if (claim in fullPayload) {
                    minimizedPayload[claim] = fullPayload[claim];
                }
            }

            return minimizedPayload as Pick<T, string>;
        } catch {
            throw new Error('Decryption Failed: Key might be wrong or data corrupted.');
        }
    }

    async delete(id: string): Promise<boolean> {
        return this.adapter.delete(id);
    }

    async has(id: string): Promise<boolean> {
        return this.adapter.has(id);
    }

    /**
     * @internal - Exposed for testing only
     */
    async getRawDocument(id: string): Promise<EncryptedDocument | null> {
        return this.adapter.load(id);
    }

    async getAllMetadata(): Promise<StoredCredentialMetadata[]> {
        return this.adapter.getAllMetadata();
    }
}
