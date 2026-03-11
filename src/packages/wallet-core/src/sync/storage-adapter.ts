/**
 * @module @mitch/wallet-core/sync/storage-adapter
 *
 * Pluggable storage adapter interface for CRDT state sync.
 *
 * Storage providers (iCloud, Google Drive, WebDAV, IPFS) only see
 * encrypted blobs — never the plaintext CRDT state.
 * The sync key is derived from the user's credential, not stored here.
 *
 * Implementations: iCloud (iOS), Google Drive (Android), WebDAV (cross-platform), IPFS (p2p).
 * All implementations are wallet-side only — never server-side.
 */

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface SyncStorageAdapter {
    /** Stable identifier for this adapter (e.g. 'icloud', 'google-drive', 'webdav') */
    readonly id: string;
    /** Human-readable name shown in wallet settings */
    readonly displayName: string;

    /** Check if this storage provider is available on this device */
    isAvailable(): Promise<boolean>;

    /** Check if user is authenticated with this storage provider */
    isAuthenticated(): Promise<boolean>;

    /** Prompt user to authenticate (opens OS auth sheet) */
    authenticate(): Promise<void>;

    /** Store an encrypted blob at a key */
    put(key: string, blob: Uint8Array): Promise<void>;

    /** Retrieve blob — returns null if key does not exist */
    get(key: string): Promise<Uint8Array | null>;

    /** Delete a key */
    delete(key: string): Promise<void>;

    /**
     * Watch a key for remote changes (optional — for real-time sync).
     * Returns an unsubscribe function.
     */
    watch?(key: string, callback: (blob: Uint8Array) => void): () => void;
}

// ---------------------------------------------------------------------------
// In-memory adapter (testing)
// ---------------------------------------------------------------------------

/**
 * In-memory storage adapter.
 * For unit tests only — does not persist across process restarts.
 */
export class InMemorySyncAdapter implements SyncStorageAdapter {
    readonly id = 'memory';
    readonly displayName = 'In-Memory (Test)';

    private store = new Map<string, Uint8Array>();
    private watchers = new Map<string, Array<(blob: Uint8Array) => void>>();

    async isAvailable(): Promise<boolean> { return true; }
    async isAuthenticated(): Promise<boolean> { return true; }
    async authenticate(): Promise<void> { /* no-op */ }

    async put(key: string, blob: Uint8Array): Promise<void> {
        this.store.set(key, blob);
        const handlers = this.watchers.get(key) ?? [];
        for (const handler of handlers) handler(blob);
    }

    async get(key: string): Promise<Uint8Array | null> {
        return this.store.get(key) ?? null;
    }

    async delete(key: string): Promise<void> {
        this.store.delete(key);
    }

    watch(key: string, callback: (blob: Uint8Array) => void): () => void {
        const handlers = this.watchers.get(key) ?? [];
        handlers.push(callback);
        this.watchers.set(key, handlers);
        return () => {
            const current = this.watchers.get(key) ?? [];
            this.watchers.set(key, current.filter(h => h !== callback));
        };
    }
}

// ---------------------------------------------------------------------------
// Unavailable adapter (stub for unimplemented providers)
// ---------------------------------------------------------------------------

/**
 * Stub adapter that reports unavailable.
 * Used as a placeholder for iCloud/Google Drive until native implementations are built.
 */
export class UnavailableSyncAdapter implements SyncStorageAdapter {
    constructor(
        readonly id: string,
        readonly displayName: string
    ) { }

    async isAvailable(): Promise<boolean> { return false; }
    async isAuthenticated(): Promise<boolean> { return false; }
    async authenticate(): Promise<void> {
        throw new Error(`${this.displayName} adapter is not yet implemented`);
    }
    async put(): Promise<void> {
        throw new Error(`${this.displayName} adapter is not yet implemented`);
    }
    async get(): Promise<null> { return null; }
    async delete(): Promise<void> { /* no-op */ }
}

/** Stub for iCloud (iOS — to be implemented in wallet-pwa) */
export const iCloudAdapter = new UnavailableSyncAdapter('icloud', 'iCloud Drive');
/** Stub for Google Drive (Android — to be implemented in wallet-pwa) */
export const googleDriveAdapter = new UnavailableSyncAdapter('google-drive', 'Google Drive');
