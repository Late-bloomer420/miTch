/* eslint-disable @typescript-eslint/no-explicit-any */
import '@testing-library/jest-dom';
// Full spec-compliant IndexedDB polyfill (fake-indexeddb) for the jsdom test env.
// This correctly fires tx.oncomplete, index cursors, and deleteDatabase — the
// hand-rolled shim below is skipped because fake-indexeddb sets globalThis.indexedDB.
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';

// Hard-reset IndexedDB before every test by swapping in a brand-new factory.
// This is fake-indexeddb's recommended isolation idiom: a fresh IDBFactory has
// no databases and no open connections, so one test's credential data cannot
// bleed into the next. We deliberately do NOT use deleteDatabase() here — it
// blocks indefinitely (onblocked, never resolving) whenever a prior connection
// to the named DB is still open, which the BrowserIndexedDBAdapter never closes,
// deadlocking the whole suite on the first test.
beforeEach(() => {
  globalThis.indexedDB = new IDBFactory(); // empty IndexedDB store per test
});

// Mock IndexedDB for jsdom environment
// vitest setup — no direct imports needed (globals: true in vitest.config.ts)

// Minimal IndexedDB shim — enough for WalletService.initialize() + getAllMetadata() to work
if (typeof globalThis.indexedDB === 'undefined') {
    const mockStore = new Map<string, unknown>();

    const makeObjectStore = () => ({
        get: (key: string) => {
            const req = { result: mockStore.get(key), onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
        getAll: () => {
            const req = { result: Array.from(mockStore.values()), onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
        getAllKeys: () => {
            const req = { result: Array.from(mockStore.keys()), onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
        put: (value: any, key?: string) => {
            const k = key ?? value?.id;
            mockStore.set(k, value);
            const req = { result: key, onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
        delete: (key: string) => {
            mockStore.delete(key);
            const req = { result: undefined, onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
        clear: () => {
            mockStore.clear();
            const req = { result: undefined, onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
    });

    const mockTransaction = {
        objectStore: () => makeObjectStore(),
        oncomplete: null as any,
        onerror: null as any,
    };

    const mockDB = {
        transaction: () => mockTransaction,
        objectStoreNames: { contains: () => true },
        createObjectStore: () => ({}),
        close: () => {},
    };

    const mockOpen = () => {
        const req = {
            result: mockDB,
            onsuccess: null as any,
            onerror: null as any,
            onupgradeneeded: null as any,
        };
        setTimeout(() => {
            req.onupgradeneeded?.({ target: req });
            req.onsuccess?.({ target: req });
        }, 0);
        return req;
    };

    (globalThis as any).indexedDB = {
        open: mockOpen,
        deleteDatabase: () => {
            mockStore.clear();
            const req = { onsuccess: null as any, onerror: null as any };
            setTimeout(() => req.onsuccess?.({ target: req }), 0);
            return req;
        },
    };
}

// jsdom doesn't implement elementFromPoint — stub it for SecureZone component
if (typeof document !== 'undefined' && !document.elementFromPoint) {
    (document as any).elementFromPoint = () => null;
}
