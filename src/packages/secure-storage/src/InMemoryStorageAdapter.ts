import type { IStorageAdapter, EncryptedDocument } from './IStorageAdapter';
import type { StoredCredentialMetadata } from '@mitch/shared-types';

/**
 * Transient in-memory storage. 
 * Useful for tests and non-browser environments.
 */
export class InMemoryStorageAdapter implements IStorageAdapter {
    private data = new Map<string, EncryptedDocument>();

    async save(entry: EncryptedDocument): Promise<void> {
        this.data.set(entry.id, entry);
    }

    async load(id: string): Promise<EncryptedDocument | null> {
        return this.data.get(id) ?? null;
    }

    async delete(id: string): Promise<boolean> {
        return this.data.delete(id);
    }

    async has(id: string): Promise<boolean> {
        return this.data.has(id);
    }

    async getAllMetadata(): Promise<StoredCredentialMetadata[]> {
        return Array.from(this.data.values()).map(r => r.indexTags);
    }

    async clear(): Promise<void> {
        this.data.clear();
    }
}
