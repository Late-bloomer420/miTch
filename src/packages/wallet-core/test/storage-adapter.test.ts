/**
 * wallet-core — storage adapter tests
 *
 * Covers UnavailableSyncAdapter behaviour (currently untested):
 * - isAvailable / isAuthenticated → false
 * - authenticate / put → throw "not yet implemented"
 * - get → returns null (graceful no-op, not a throw)
 * - delete → no-op
 * Pre-built cloud stubs (iCloudAdapter, googleDriveAdapter) are also checked.
 */

import { describe, it, expect } from 'vitest';
import {
    UnavailableSyncAdapter,
    iCloudAdapter,
    googleDriveAdapter,
} from '../src/sync/storage-adapter.js';

// ─── UnavailableSyncAdapter ───────────────────────────────────────────────────

describe('UnavailableSyncAdapter', () => {
    const adapter = new UnavailableSyncAdapter('test-stub', 'Test Stub');

    it('id and displayName are set by constructor', () => {
        expect(adapter.id).toBe('test-stub');
        expect(adapter.displayName).toBe('Test Stub');
    });

    it('isAvailable() resolves to false', async () => {
        expect(await adapter.isAvailable()).toBe(false);
    });

    it('isAuthenticated() resolves to false', async () => {
        expect(await adapter.isAuthenticated()).toBe(false);
    });

    it('authenticate() throws "not yet implemented"', async () => {
        await expect(adapter.authenticate()).rejects.toThrow('not yet implemented');
    });

    it('authenticate() error message contains displayName', async () => {
        await expect(adapter.authenticate()).rejects.toThrow('Test Stub');
    });

    it('put() throws "not yet implemented"', async () => {
        await expect(adapter.put('key', new Uint8Array([1]))).rejects.toThrow('not yet implemented');
    });

    it('get() returns null (graceful — does not throw)', async () => {
        const result = await adapter.get('any-key');
        expect(result).toBeNull();
    });

    it('delete() resolves without throwing (no-op)', async () => {
        await expect(adapter.delete('any-key')).resolves.toBeUndefined();
    });

    it('does NOT expose a watch() method', () => {
        // UnavailableSyncAdapter has no watch — optional interface method should be absent
        expect((adapter as any).watch).toBeUndefined();
    });
});

describe('UnavailableSyncAdapter — multiple instances are independent', () => {
    const a = new UnavailableSyncAdapter('a', 'Adapter A');
    const b = new UnavailableSyncAdapter('b', 'Adapter B');

    it('IDs are independent', () => {
        expect(a.id).toBe('a');
        expect(b.id).toBe('b');
    });

    it('error messages contain respective displayNames', async () => {
        await expect(a.authenticate()).rejects.toThrow('Adapter A');
        await expect(b.authenticate()).rejects.toThrow('Adapter B');
    });
});

// ─── iCloudAdapter ────────────────────────────────────────────────────────────

describe('iCloudAdapter (pre-built stub)', () => {
    it('id is "icloud"', () => expect(iCloudAdapter.id).toBe('icloud'));
    it('displayName is "iCloud Drive"', () => expect(iCloudAdapter.displayName).toBe('iCloud Drive'));
    it('isAvailable() → false', async () => expect(await iCloudAdapter.isAvailable()).toBe(false));
    it('isAuthenticated() → false', async () => expect(await iCloudAdapter.isAuthenticated()).toBe(false));
    it('authenticate() → throws', async () => {
        await expect(iCloudAdapter.authenticate()).rejects.toThrow();
    });
    it('get() → null', async () => {
        expect(await iCloudAdapter.get('any')).toBeNull();
    });
    it('delete() → resolves', async () => {
        await expect(iCloudAdapter.delete('any')).resolves.toBeUndefined();
    });
});

// ─── googleDriveAdapter ───────────────────────────────────────────────────────

describe('googleDriveAdapter (pre-built stub)', () => {
    it('id is "google-drive"', () => expect(googleDriveAdapter.id).toBe('google-drive'));
    it('displayName is "Google Drive"', () => expect(googleDriveAdapter.displayName).toBe('Google Drive'));
    it('isAvailable() → false', async () => expect(await googleDriveAdapter.isAvailable()).toBe(false));
    it('isAuthenticated() → false', async () => expect(await googleDriveAdapter.isAuthenticated()).toBe(false));
    it('authenticate() → throws', async () => {
        await expect(googleDriveAdapter.authenticate()).rejects.toThrow();
    });
    it('get() → null', async () => {
        expect(await googleDriveAdapter.get('any')).toBeNull();
    });
    it('delete() → resolves', async () => {
        await expect(googleDriveAdapter.delete('any')).resolves.toBeUndefined();
    });
});
