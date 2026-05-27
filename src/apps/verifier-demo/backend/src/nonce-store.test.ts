import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NonceStore } from './nonce-store';

vi.mock('fs', () => ({
    default: {
        existsSync: vi.fn(() => false),
        readFileSync: vi.fn(() => ''),
        writeFileSync: vi.fn(),
        renameSync: vi.fn(),
    },
    existsSync: vi.fn(() => false),
    readFileSync: vi.fn(() => ''),
    writeFileSync: vi.fn(),
    renameSync: vi.fn(),
}));

import fs from 'fs';

describe('NonceStore', () => {
    const t0 = 1_000_000;

    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('has()', () => {
        it('returns false for unknown key', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            expect(store.has('unknown', t0)).toBe(false);
        });

        it('returns true for key within TTL', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            store.add('key1', t0);
            expect(store.has('key1', t0 + 1000)).toBe(true);
        });

        it('returns false and evicts key after TTL expires', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            store.add('key1', t0);
            expect(store.has('key1', t0 + 61_000)).toBe(false);
        });
    });

    describe('add()', () => {
        it('adds a key with correct expiry', () => {
            const store = new NonceStore({ ttlMs: 5_000, maxEntries: 100 });
            store.add('key1', t0);
            expect(store.has('key1', t0 + 4_000)).toBe(true);
            expect(store.has('key1', t0 + 6_000)).toBe(false);
        });
    });

    describe('checkAndAdd()', () => {
        it('returns false on first use (not yet seen)', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            expect(store.checkAndAdd('nonce-1', t0)).toBe(false);
        });

        it('returns true on second use — replay detected', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            store.checkAndAdd('nonce-1', t0);
            expect(store.checkAndAdd('nonce-1', t0 + 100)).toBe(true);
        });

        it('returns false again after TTL expires (nonce can be reused)', () => {
            const store = new NonceStore({ ttlMs: 1_000, maxEntries: 100 });
            store.checkAndAdd('nonce-exp', t0);
            expect(store.checkAndAdd('nonce-exp', t0 + 2_000)).toBe(false);
        });
    });

    describe('LRU eviction', () => {
        it('evicts oldest entry when maxEntries is exceeded', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 3 });
            store.add('oldest', t0);
            store.add('middle', t0 + 1);
            store.add('newest', t0 + 2);
            // Adding a 4th entry should evict 'oldest'
            store.add('fourth', t0 + 3);
            expect(store.has('oldest', t0 + 4)).toBe(false);
            expect(store.has('fourth', t0 + 4)).toBe(true);
        });
    });

    describe('cleanupExpired()', () => {
        it('removes expired entries but keeps valid ones', () => {
            // 'old' was added 70s ago (now already expired); 'recent' was added 5s ago (still valid)
            const recent = t0;
            const old = t0 - 70_000;
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            store.add('old-key', old);   // expiresAt = old + 60s = t0 - 10s (expired)
            store.add('recent-key', recent); // expiresAt = t0 + 60s (valid)

            store.cleanupExpired(t0);
            expect(store.has('old-key', t0)).toBe(false);
            expect(store.has('recent-key', t0 + 1_000)).toBe(true);
        });
    });

    describe('loadFromDisk()', () => {
        it('does nothing when no persistencePath is configured', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            store.loadFromDisk(); // no-op
            expect(fs.existsSync).not.toHaveBeenCalled();
        });

        it('does nothing when the persistence file does not exist', () => {
            vi.mocked(fs.existsSync).mockReturnValue(false);
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            store.loadFromDisk();
            expect(fs.readFileSync).not.toHaveBeenCalled();
        });

        it('restores non-expired entries from a valid JSON file', () => {
            const future = Date.now() + 60_000;
            const state = { version: 1, entries: [['restored-key', future]] };
            vi.mocked(fs.existsSync).mockReturnValue(true);
            vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(state));

            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            store.loadFromDisk();
            expect(store.has('restored-key')).toBe(true);
        });

        it('skips already-expired entries from disk', () => {
            const past = Date.now() - 1;
            const state = { version: 1, entries: [['expired-key', past]] };
            vi.mocked(fs.existsSync).mockReturnValue(true);
            vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(state));

            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            store.loadFromDisk();
            expect(store.has('expired-key')).toBe(false);
        });

        it('handles corrupted JSON gracefully without throwing', () => {
            vi.mocked(fs.existsSync).mockReturnValue(true);
            vi.mocked(fs.readFileSync).mockReturnValue('not valid json {{{');

            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            expect(() => store.loadFromDisk()).not.toThrow();
        });

        it('handles wrong version gracefully', () => {
            const state = { version: 99, entries: [['key', Date.now() + 60_000]] };
            vi.mocked(fs.existsSync).mockReturnValue(true);
            vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(state));

            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            store.loadFromDisk();
            expect(store.has('key')).toBe(false);
        });
    });

    describe('flushToDisk()', () => {
        it('does nothing when no persistencePath is configured', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            store.flushToDisk();
            expect(fs.writeFileSync).not.toHaveBeenCalled();
        });

        it('writes to a tmp file then renames atomically', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            store.add('key1', t0);
            store.flushToDisk();
            expect(fs.writeFileSync).toHaveBeenCalledWith('/tmp/nonces.json.tmp', expect.any(String));
            expect(fs.renameSync).toHaveBeenCalledWith('/tmp/nonces.json.tmp', '/tmp/nonces.json');
        });

        it('written JSON is parseable and contains current entries', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, persistencePath: '/tmp/nonces.json' });
            store.add('key1', t0);

            let written = '';
            vi.mocked(fs.writeFileSync).mockImplementation((_path: any, data: any) => {
                written = data as string;
            });

            store.flushToDisk();
            const parsed = JSON.parse(written);
            expect(parsed.version).toBe(1);
            expect(Array.isArray(parsed.entries)).toBe(true);
        });
    });

    describe('close()', () => {
        it('clears the cleanup timer', () => {
            vi.useFakeTimers();
            const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval');
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100, cleanupIntervalMs: 30_000 });
            store.close();
            expect(clearIntervalSpy).toHaveBeenCalled();
            clearIntervalSpy.mockRestore();
        });

        it('does not throw if no cleanup timer was set', () => {
            const store = new NonceStore({ ttlMs: 60_000, maxEntries: 100 });
            expect(() => store.close()).not.toThrow();
        });
    });
});
