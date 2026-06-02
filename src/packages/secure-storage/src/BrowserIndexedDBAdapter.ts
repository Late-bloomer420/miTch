import type { IStorageAdapter, EncryptedDocument } from './IStorageAdapter';
import type { StoredCredentialMetadata } from '@mitch/shared-types';

const DB_NAME = 'mitch_wallet_v1';
const STORE_NAME = 'credentials';

/**
 * Browser-native storage using IndexedDB.
 */
export class BrowserIndexedDBAdapter implements IStorageAdapter {
    private dbPromise: Promise<IDBDatabase>;

    constructor() {
        this.dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
            if (typeof indexedDB === 'undefined') {
                reject(new Error('IndexedDB is not available in this environment.'));
                return;
            }

            const request = indexedDB.open(DB_NAME, 1);

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
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
    }

    async save(entry: EncryptedDocument): Promise<void> {
        const db = await this.dbPromise;
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readwrite');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.put(entry);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    async load(id: string): Promise<EncryptedDocument | null> {
        const db = await this.dbPromise;
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.get(id);
            request.onsuccess = () => resolve(request.result as EncryptedDocument ?? null);
            request.onerror = () => reject(request.error);
        });
    }

    async delete(id: string): Promise<boolean> {
        const db = await this.dbPromise;
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readwrite');
            const store = transaction.objectStore(STORE_NAME);
            const getReq = store.get(id);
            getReq.onsuccess = () => {
                if (!getReq.result) {
                    resolve(false);
                    return;
                }
                const delReq = store.delete(id);
                delReq.onsuccess = () => resolve(true);
                delReq.onerror = () => reject(delReq.error);
            };
            getReq.onerror = () => reject(getReq.error);
        });
    }

    async has(id: string): Promise<boolean> {
        const db = await this.dbPromise;
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.count(id);
            request.onsuccess = () => resolve(request.result > 0);
            request.onerror = () => reject(request.error);
        });
    }

    async getAllMetadata(): Promise<StoredCredentialMetadata[]> {
        const db = await this.dbPromise;
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.getAll();
            request.onsuccess = () => {
                const results = request.result as EncryptedDocument[];
                resolve(results.map(r => r.indexTags));
            };
            request.onerror = () => reject(request.error);
        });
    }

    async clear(): Promise<void> {
        await new Promise<void>((resolve, reject) => {
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
            request.onblocked = () => reject(new Error('IndexedDB delete blocked.'));
        });
    }
}
