import { SecureStorage } from '@mitch/secure-storage';
import type { StoredCredentialMetadata } from '@askmi/shared-types';
import type { ICredentialRepository } from './ICredentialRepository';

/**
 * Concrete implementation of ICredentialRepository using @mitch/secure-storage.
 */
export class EncryptedCredentialRepository implements ICredentialRepository {
    constructor(private storage: SecureStorage) {}

    async save(id: string, payload: Record<string, unknown>, metadata: StoredCredentialMetadata): Promise<void> {
        await this.storage.save(id, payload, metadata);
    }

    async load<T = Record<string, unknown>>(id: string): Promise<T | null> {
        return this.storage.load<T>(id);
    }

    async loadSelective<T extends Record<string, unknown>>(id: string, claims: string[]): Promise<Pick<T, string> | null> {
        return this.storage.loadSelectiveClaims<T>(id, claims);
    }

    async delete(id: string): Promise<boolean> {
        return this.storage.delete(id);
    }

    async listMetadata(): Promise<StoredCredentialMetadata[]> {
        return this.storage.getAllMetadata();
    }

    async exists(id: string): Promise<boolean> {
        return this.storage.has(id);
    }
}
