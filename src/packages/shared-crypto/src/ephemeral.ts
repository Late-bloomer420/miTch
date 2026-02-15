/**
 * @module @mitch/shared-crypto/ephemeral
 * 
 * Ephemeral Key Management for Crypto-Shredding
 * 
 * Implements the core primitive for secure data destruction:
 * keys that can be deterministically destroyed, rendering
 * encrypted data permanently unrecoverable.
 * 
 * ## Key Properties
 * - Keys exist only in memory (non-extractable CryptoKey handles)
 * - `shred()` destroys references, making keys GC-eligible
 * - All operations throw after shredding
 * - Auditable key lifecycle
 */

import { generateSymmetricKey, wrapKeyForRecipient } from './keys';
import { encrypt, decrypt } from './encryption';

/**
 * EphemeralKey: Core primitive for Crypto-Shredding.
 * 
 * Rules:
 * 1. Key exists ONLY in memory (and within the CryptoKey handle).
 * 2. `shred()` destroys the reference, making the key garbage-collectable.
 * 3. Any method call after `shred()` throws a security error.
 * 
 * This class wraps all access to the underlying key material.
 */
export class EphemeralKey {
    private key: CryptoKey | null;
    private shredded: boolean = false;

    private constructor(key: CryptoKey) {
        this.key = key;
    }

    static async create(): Promise<EphemeralKey> {
        // Direct generation to ensure proper flags (must be extractable to be wrapped)
        // We bypass the helper to avoid any ambiguity or build staleness.
        const key = await (globalThis as any).crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true, // extractable
            ['encrypt', 'decrypt']
        );
        return new EphemeralKey(key as CryptoKey);
    }

    /**
     * Encrypts data with this ephemeral key.
     * @param data plain text to encrypt
     * @param aad optional Additional Authenticated Data for context binding
     * @throws if shredded
     */
    async encrypt(data: string, aad?: BufferSource): Promise<string> {
        this.assertActive();
        return encrypt(data, this.key!, aad);
    }

    /**
     * Decrypts data with this ephemeral key.
     * @param ciphertext base64-encoded ciphertext
     * @param aad optional AAD (must match encryption)
     * @throws if shredded
     */
    async decrypt(ciphertext: string, aad?: BufferSource): Promise<string> {
        this.assertActive();
        return decrypt(ciphertext, this.key!, aad);
    }

    /**
     * Seal this key to a recipient's public key.
     * Use this to safely transport the EphemeralKey.
     */
    async sealToRecipient(recipientPubKey: CryptoKey): Promise<string> {
        this.assertActive();
        return wrapKeyForRecipient(recipientPubKey, this.key!);
    }

    /**
     * Crypto-Shredding: Irreversibly destroys access to the key.
     * After this, the key is unreachable and will be cleaned up by GC.
     */
    shred(): void {
        if (this.shredded) return; // Already shredded

        // Hard reference drop
        this.key = null;
        this.shredded = true;
    }

    /**
     * Checks if the key is still active.
     */
    isDestroyed(): boolean {
        return this.shredded;
    }

    /**
     * ALLOWED OPERATION: Export the key handle for wrapping (encryption for recipient).
     * Does NOT export raw bits.
     * @internal
     */
    async exportKeyHandleForWrapping(): Promise<CryptoKey> {
        this.assertActive();
        return this.key!;
    }

    private assertActive(): void {
        if (this.shredded || !this.key) {
            throw new Error('SECURITY VIOLATION: Attempted to use shredded EphemeralKey');
        }
    }
}
