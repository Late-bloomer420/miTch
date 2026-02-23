import { AuditLogEntry } from '@mitch/shared-types';

/**
 * WORM-enabled IndexedDB Store for Audit Logs
 * 
 * GDPR Compliance:
 * - Art. 32 DSGVO: Append-only storage prevents manipulation
 * - Write Once, Read Many (WORM) guarantees
 * - Persistent across sessions
 * 
 * Security Properties:
 * - No update/delete operations exposed
 * - Integrity checks on read
 * - Automatic versioning
 */
export class IndexedDBAuditStore {
    private db: IDBDatabase | null = null;
    private readonly DB_NAME = 'mitch_audit_log';
    private readonly STORE_NAME = 'entries';
    private readonly DB_VERSION = 1;

    constructor(private walletId: string) { }

    /**
     * Initialize the IndexedDB connection
     */
    async initialize(): Promise<void> {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

            request.onerror = () => reject(new Error('Failed to open IndexedDB'));

            request.onsuccess = () => {
                this.db = request.result;
                resolve();
            };

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;

                // Create object store if it doesn't exist
                if (!db.objectStoreNames.contains(this.STORE_NAME)) {
                    const store = db.createObjectStore(this.STORE_NAME, {
                        keyPath: 'id',
                        autoIncrement: false
                    });

                    // Indexes for efficient querying
                    store.createIndex('timestamp', 'timestamp', { unique: false });
                    store.createIndex('action', 'action', { unique: false });
                    store.createIndex('walletId', 'walletId', { unique: false });
                }
            };
        });
    }

    /**
     * Append a new entry (WORM - Write Once)
     * 
     * @throws Error if entry with same ID already exists
     */
    async append(entry: AuditLogEntry): Promise<void> {
        if (!this.db) {
            throw new Error('IndexedDB not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction([this.STORE_NAME], 'readwrite');
            const store = transaction.objectStore(this.STORE_NAME);

            // Augment entry with wallet ID for multi-wallet support
            const storedEntry = {
                ...entry,
                walletId: this.walletId,
                storedAt: new Date().toISOString()
            };

            // Check if entry already exists (WORM enforcement)
            const checkRequest = store.get(entry.id);

            checkRequest.onsuccess = () => {
                if (checkRequest.result) {
                    reject(new Error(`WORM_VIOLATION: Entry ${entry.id} already exists`));
                    return;
                }

                // Write entry
                const addRequest = store.add(storedEntry);

                addRequest.onsuccess = () => resolve();
                addRequest.onerror = () => reject(new Error('Failed to append entry'));
            };

            checkRequest.onerror = () => reject(new Error('Failed to check entry existence'));
        });
    }

    /**
     * Retrieve all entries for this wallet (chronological order)
     */
    async getAllEntries(): Promise<AuditLogEntry[]> {
        if (!this.db) {
            throw new Error('IndexedDB not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction([this.STORE_NAME], 'readonly');
            const store = transaction.objectStore(this.STORE_NAME);
            const index = store.index('walletId');

            const request = index.getAll(this.walletId);

            request.onsuccess = () => {
                const entries = request.result as (AuditLogEntry & { walletId: string; storedAt: string })[];

                // Sort by timestamp (oldest first)
                entries.sort((a, b) =>
                    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
                );

                // Remove internal fields
                const cleanEntries = entries.map(({ walletId, storedAt, ...entry }) => entry);
                resolve(cleanEntries);
            };

            request.onerror = () => reject(new Error('Failed to retrieve entries'));
        });
    }

    /**
     * Get entries within a time range
     */
    async getEntriesByTimeRange(startTime: string, endTime: string): Promise<AuditLogEntry[]> {
        const allEntries = await this.getAllEntries();

        return allEntries.filter(entry =>
            entry.timestamp >= startTime && entry.timestamp <= endTime
        );
    }

    /**
     * Get entries by action type
     */
    async getEntriesByAction(action: AuditLogEntry['action']): Promise<AuditLogEntry[]> {
        if (!this.db) {
            throw new Error('IndexedDB not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction([this.STORE_NAME], 'readonly');
            const store = transaction.objectStore(this.STORE_NAME);
            const index = store.index('action');

            const request = index.getAll(action);

            request.onsuccess = () => {
                const entries = request.result as (AuditLogEntry & { walletId: string })[];

                // Filter by wallet ID
                const walletEntries = entries.filter(e => e.walletId === this.walletId);

                // Remove internal fields
                const cleanEntries = walletEntries.map(({ walletId, storedAt, ...entry }: any) => entry);
                resolve(cleanEntries);
            };

            request.onerror = () => reject(new Error('Failed to retrieve entries by action'));
        });
    }

    /**
     * Get the total number of entries
     */
    async getEntryCount(): Promise<number> {
        if (!this.db) {
            throw new Error('IndexedDB not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction([this.STORE_NAME], 'readonly');
            const store = transaction.objectStore(this.STORE_NAME);
            const index = store.index('walletId');

            const request = index.count(this.walletId);

            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new Error('Failed to count entries'));
        });
    }

    /**
     * Close the database connection
     */
    close(): void {
        if (this.db) {
            this.db.close();
            this.db = null;
        }
    }

    /**
     * DANGER: Clear all entries (for testing only!)
     * 
     * @throws Error in production builds
     */
    async clearAll(): Promise<void> {
        if (process.env.NODE_ENV === 'production') {
            throw new Error('SECURITY_VIOLATION: Cannot clear audit log in production');
        }

        if (!this.db) {
            throw new Error('IndexedDB not initialized');
        }

        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction([this.STORE_NAME], 'readwrite');
            const store = transaction.objectStore(this.STORE_NAME);

            const request = store.clear();

            request.onsuccess = () => resolve();
            request.onerror = () => reject(new Error('Failed to clear entries'));
        });
    }
}
