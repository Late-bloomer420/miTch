import '@testing-library/jest-dom';

// Mock IndexedDB for jsdom environment
import { vi } from 'vitest';

// Minimal IndexedDB shim — enough for WalletService.initialize() to not crash
if (typeof globalThis.indexedDB === 'undefined') {
    const mockStore = new Map<string, unknown>();
    
    const mockTransaction = {
        objectStore: () => ({
            get: (key: string) => {
                const req = { result: mockStore.get(key), onsuccess: null as any, onerror: null as any };
                setTimeout(() => req.onsuccess?.({ target: req }), 0);
                return req;
            },
            put: (value: unknown, key: string) => {
                mockStore.set(key, value);
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
        }),
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
