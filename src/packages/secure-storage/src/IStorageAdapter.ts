import type { StoredCredentialMetadata } from '@askmi/shared-types';

/**
 * Encrypted document structure for storage adapters.
 */
export interface EncryptedDocument {
    id: string;
    ciphertext: string;
    indexTags: StoredCredentialMetadata;
}

/**
 * Interface for pluggable storage backends.
 * Allows miTch to run in Browser (IndexedDB), Node.js (File/SQLite), or TEE.
 */
export interface IStorageAdapter {
    /**
     * Save an encrypted document.
     */
    save(entry: EncryptedDocument): Promise<void>;

    /**
     * Load an encrypted document by ID.
     */
    load(id: string): Promise<EncryptedDocument | null>;

    /**
     * Delete a document by ID.
     */
    delete(id: string): Promise<boolean>;

    /**
     * Check if a document exists.
     */
    has(id: string): Promise<boolean>;

    /**
     * List metadata for all stored documents.
     */
    getAllMetadata(): Promise<StoredCredentialMetadata[]>;

    /**
     * Completely clear the storage (factory reset).
     */
    clear(): Promise<void>;
}
