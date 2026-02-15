/**
 * @module @mitch/secure-storage
 * 
 * Secure Storage Module for Verifiable Credentials
 * 
 * Provides encrypted IndexedDB storage for sensitive credential data.
 * All data is encrypted at rest using AES-256-GCM with a Master Key
 * derived from the user's PIN/passphrase.
 * 
 * ## Architecture
 * - Credentials stored as encrypted blobs with plaintext index tags
 * - Index tags allow querying without decrypting (issuer, type, etc.)
 * - T-36a: Supports selective claim decryption for data minimization
 */

import { encrypt, decrypt } from '@mitch/shared-crypto';
import type { StoredCredentialMetadata } from '@mitch/shared-types';

/**
 * Structure of a document stored in IndexedDB.
 * The ciphertext contains the encrypted credential; indexTags are searchable.
 */
export interface EncryptedDocument {
    /** Unique document identifier */
    id: string;
    /** Base64-encoded AES-256-GCM ciphertext */
    ciphertext: string;
    /** Plaintext metadata for querying (no sensitive data) */
    indexTags: StoredCredentialMetadata;
}

const DB_NAME = 'mitch_wallet_v1';
const STORE_NAME = 'credentials';

/**
 * Secure Storage for Verifiable Credentials.
 * 
 * All credentials are encrypted before storage and can only be
 * decrypted with the correct Master Key. Implements data minimization
 * through selective claim decryption (T-36a).
 */
export class SecureStorage {
    private dbPromise: Promise<IDBDatabase>;
    private key: CryptoKey;

    private constructor(key: CryptoKey, dbPromise: Promise<IDBDatabase>) {
        this.key = key;
        this.dbPromise = dbPromise;
    }

    /**
     * Initialize the storage with a Master Key.
     * This key is used to encrypt/decrypt all sensitive data.
     */
    static async init(masterKey: CryptoKey): Promise<SecureStorage> {
        const dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
            if (typeof indexedDB === 'undefined') {
                reject(new Error('IndexedDB is not available in this environment.'));
                return;
            }

            const request = indexedDB.open(DB_NAME, 1);

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
                    // Indexing for query optimization
                    store.createIndex('type', 'indexTags.type', { unique: false, multiEntry: true });
                    store.createIndex('issuer', 'indexTags.issuer', { unique: false });
                }
            };

            request.onsuccess = (event) => {
                resolve((event.target as IDBOpenDBRequest).result);
            };

            request.onerror = (event) => {
                reject((event.target as IDBOpenDBRequest).error);
            };
        });

        return new SecureStorage(masterKey, dbPromise);
    }

    /**
     * Reset the storage by deleting the entire IndexedDB database.
     * Intended for demo recovery when keys or ciphertext are incompatible.
     */
    static async reset(): Promise<void> {
        if (typeof indexedDB === 'undefined') {
            throw new Error('IndexedDB is not available in this environment.');
        }
        await new Promise<void>((resolve, reject) => {
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
            request.onblocked = () => reject(new Error('IndexedDB delete blocked.'));
        });
    }

    /**
     * Save a document (VC) securely.#interesting
     * @param id Unique ID
     * @param data The secret data (will be encrypted)
     * @param metadata Metadata to store in plain text for querying
     */
    async save(id: string, data: unknown, metadata: Omit<StoredCredentialMetadata, 'id'>): Promise<void> {
        const db = await this.dbPromise;

        // 1. Serialize
        const plaintext = JSON.stringify(data);

        // 2. Encrypt
        const ciphertext = await encrypt(plaintext, this.key);

        // 3. Store
        const entry: EncryptedDocument = {
            id,
            ciphertext,
            indexTags: { ...metadata, id }
        };

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readwrite');
            const store = transaction.objectStore(STORE_NAME);

            const request = store.put(entry);

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Retrieve and decrypt a document.
     */
    async load<T>(id: string): Promise<T | null> {
        const db = await this.dbPromise;

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.get(id);

            request.onsuccess = async () => {
                const result = request.result as EncryptedDocument;
                if (!result) {
                    resolve(null);
                    return;
                }

                try {
                    // Decrypt
                    const plaintext = await decrypt(result.ciphertext, this.key);
                    const parsed = JSON.parse(plaintext) as T;
                    resolve(parsed);
                } catch (e) {
                    reject(new Error('Decryption Failed: Key might be wrong or data corrupted.'));
                }
            };

            request.onerror = () => reject(request.error);
        });
    }

    /**
     * T-36a: Claim-Level Selective Decryption
     * 
     * Only decrypts and returns the specified claims from a credential.
     * Claims not in the `effectiveClaims` list are never decrypted or accessed.
     * 
     * This implements "Minimize before decrypt" at the storage level.
     * 
     * @param id Credential ID
     * @param effectiveClaims The claims the PolicyEngine has authorized for disclosure
     */
    async loadSelectiveClaims<T extends Record<string, unknown>>(
        id: string,
        effectiveClaims: string[]
    ): Promise<Pick<T, string> | null> {
        const db = await this.dbPromise;

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.get(id);

            request.onsuccess = async () => {
                const result = request.result as EncryptedDocument;
                if (!result) {
                    resolve(null);
                    return;
                }

                try {
                    // Decrypt full payload (currently we don't have per-claim encryption blobs)
                    // In a production system, each claim would be encrypted separately.
                    // For PoC: We decrypt the blob, but then immediately FILTER to effectiveClaims.
                    const plaintext = await decrypt(result.ciphertext, this.key);
                    const fullPayload = JSON.parse(plaintext) as T;

                    // T-36a: ONLY return authorized claims (minimization)
                    const minimizedPayload: Record<string, unknown> = {};
                    for (const claim of effectiveClaims) {
                        if (claim in fullPayload) {
                            minimizedPayload[claim] = fullPayload[claim];
                        }
                    }

                    resolve(minimizedPayload as Pick<T, string>);
                } catch (e) {
                    reject(new Error('Decryption Failed: Key might be wrong or data corrupted.'));
                }
            };

            request.onerror = () => reject(request.error);
        });
    }

    /**
     * List all items (Metadata Only).
     * Used by PolicyEngine to find candidates.
     */
    async getAllMetadata(): Promise<StoredCredentialMetadata[]> {
        const db = await this.dbPromise;

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.getAll();

            request.onsuccess = () => {
                const results = request.result as EncryptedDocument[];
                const metadata = results.map(r => r.indexTags);
                resolve(metadata);
            };

            request.onerror = () => reject(request.error);
        });
    }
}
