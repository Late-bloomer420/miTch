import { SecureStorage } from '@mitch/secure-storage';
import { StoredCredentialMetadata } from '@mitch/shared-types';

export class CredentialRepository {
  constructor(private storage: SecureStorage) {}

  /**
   * Add a credential to the wallet (persisted encrypted in SecureStorage).
   */
  async addCredential(
    id: string,
    payload: Record<string, unknown>,
    metadata: { issuer: string; type: string[]; claims: string[]; issuedAt: string }
  ): Promise<void> {
    await this.storage.save(id, payload, metadata);
  }

  /**
   * Delete a credential from the wallet.
   * Returns true if the credential existed and was removed, false otherwise.
   */
  async deleteCredential(id: string): Promise<boolean> {
    return this.storage.delete(id);
  }

  /**
   * Get all credential metadata (without decrypting payloads).
   */
  async getCredentials(): Promise<StoredCredentialMetadata[]> {
    return this.storage.getAllMetadata();
  }

  /**
   * Load a specific credential's decrypted payload.
   */
  async loadCredential<T = Record<string, unknown>>(id: string): Promise<T | null> {
    return this.storage.load<T>(id);
  }

  /**
   * Get raw encrypted document for a credential (test/debug only).
   */
  async getRawCredentialDocument(id: string) {
    return this.storage.getRawDocument(id);
  }
}
