import type { StoredCredentialMetadata } from '@mitch/shared-types';

/**
 * Interface for credential lifecycle management.
 * Extracted from WalletService for Phase 2.2 decomposition.
 */
export interface ICredentialRepository {
    /**
     * Add or update a credential.
     */
    save(id: string, payload: Record<string, unknown>, metadata: StoredCredentialMetadata): Promise<void>;

    /**
     * Load a credential's full decrypted payload.
     */
    load<T = Record<string, unknown>>(id: string): Promise<T | null>;

    /**
     * Load only specific authorized claims (Minimization).
     */
    loadSelective<T extends Record<string, unknown>>(id: string, claims: string[]): Promise<Pick<T, string> | null>;

    /**
     * Remove a credential.
     */
    delete(id: string): Promise<boolean>;

    /**
     * List all available credentials (metadata only).
     */
    listMetadata(): Promise<StoredCredentialMetadata[]>;

    /**
     * Check if a credential exists.
     */
    exists(id: string): Promise<boolean>;
}
