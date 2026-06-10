/**
 * Durable Holder-Key Custody (Proof-Randomization Increment 2 / C1)
 *
 * A sibling IndexedDB (separate from the credential store `mitch_wallet_v1`)
 * that natively persists non-extractable holder `CryptoKey` handles via the
 * Structured Clone Algorithm — the private bits never become extractable, but
 * the handle survives page reloads. This is impossible with localStorage (which
 * forces strings) and inappropriate for the encrypting secure-storage path
 * (which JSON-serializes its payloads).
 *
 * Raw IndexedDB, mirroring `secure-storage/BrowserIndexedDBAdapter.ts`. Keyed by
 * `credentialId`, with a secondary `poolId` index so a whole batch pool can be
 * shredded in one range delete. All ops degrade to no-ops where IndexedDB is
 * unavailable (the in-memory cache in WalletService remains the session path).
 */

const DB_NAME = 'mitch_holder_keys_v1';
const STORE_NAME = 'holder_keys';

/** A durably-stored holder key for one batch-issued single-use credential. */
export interface StoredHolderKey {
  /** Stored credential id this key signs for (primary key). */
  credentialId: string;
  /** Batch pool id — indexed, for whole-pool lifecycle cleanup. */
  poolId: string;
  /** Public half (for debugging / matching; the private key is non-extractable). */
  publicKeyJwk: JsonWebKey;
  /** Native non-extractable private key handle (structured-cloned, never serialized). */
  privateKey: CryptoKey;
  /** Creation timestamp (ms). */
  createdAt: number;
}

function idbAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

let dbPromise: Promise<IDBDatabase> | null = null;
let openDbInstance: IDBDatabase | null = null;

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'credentialId' });
        store.createIndex('poolId', 'poolId', { unique: false });
      }
    };
    request.onsuccess = (event) => {
      openDbInstance = (event.target as IDBOpenDBRequest).result;
      resolve(openDbInstance);
    };
    request.onerror = (event) => reject((event.target as IDBOpenDBRequest).error);
  });
  return dbPromise;
}

/** Durably store (or replace) one holder key. No-op where IndexedDB is unavailable. */
export async function putKey(record: StoredHolderKey): Promise<void> {
  if (!idbAvailable()) return;
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Fetch the holder key for a credential id, or undefined if absent/unavailable. */
export async function getKey(credentialId: string): Promise<StoredHolderKey | undefined> {
  if (!idbAvailable()) return undefined;
  const db = await openDb();
  return new Promise<StoredHolderKey | undefined>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(credentialId);
    req.onsuccess = () => resolve(req.result as StoredHolderKey | undefined);
    req.onerror = () => reject(req.error);
  });
}

/** Shred one holder key (shred-on-burn after a successful presentation). */
export async function deleteKey(credentialId: string): Promise<void> {
  if (!idbAvailable()) return;
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(credentialId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Shred every holder key in a batch pool (whole-pool lifecycle cleanup) via the poolId index. */
export async function deletePoolKeys(poolId: string): Promise<void> {
  if (!idbAvailable()) return;
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const index = tx.objectStore(STORE_NAME).index('poolId');
    const cursorReq = index.openCursor(IDBKeyRange.only(poolId));
    cursorReq.onsuccess = () => {
      const cursor = cursorReq.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Test-only: close + drop the cached connection so a fresh `deleteDatabase` is not blocked. */
export function __resetConnectionForTests(): void {
  openDbInstance?.close();
  openDbInstance = null;
  dbPromise = null;
}
