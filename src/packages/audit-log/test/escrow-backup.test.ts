import { describe, it, expect, beforeAll, vi } from 'vitest';
import { EscrowBackupService } from '../src/storage/escrow-backup';
import type { AuditLogEntry } from '@mitch/shared-types';

const makeEntry = (id: string): AuditLogEntry => ({
    id,
    timestamp: new Date().toISOString(),
    action: 'KEY_CREATED',
    subjectId: 'test-subject',
    metadata: {},
});

let dpaKeyPair: CryptoKeyPair;

beforeAll(async () => {
    dpaKeyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
    );
});

describe('EscrowBackupService.createBackup()', () => {
    it('returns EncryptedBackup with all required fields', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        const entries = [makeEntry('e1'), makeEntry('e2')];
        const backup = await service.createBackup(entries, 'wallet-001');

        expect(backup.backupId).toBeTruthy();
        expect(backup.walletId).toBe('wallet-001');
        expect(backup.encryptedData).toBeTruthy();
        expect(backup.encryptedKey).toBeTruthy();
        expect(backup.createdAt).toBeTruthy();
        expect(backup.expiresAt).toBeTruthy();
        expect(backup.metadata.entryCount).toBe(2);
    });

    it('throws when entries array is empty', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        await expect(service.createBackup([], 'wallet-001')).rejects.toThrow();
    });

    it('sets expiresAt based on retentionDays', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 7,
        });

        const before = Date.now();
        const backup = await service.createBackup([makeEntry('e1')], 'wallet-001');
        const after = Date.now();

        const expiresMs = new Date(backup.expiresAt).getTime();
        const expectedMin = before + 7 * 24 * 60 * 60 * 1000;
        const expectedMax = after + 7 * 24 * 60 * 60 * 1000;

        expect(expiresMs).toBeGreaterThanOrEqual(expectedMin);
        expect(expiresMs).toBeLessThanOrEqual(expectedMax);
    });

    it('encryptedData contains IV prefix separated by colon', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        const backup = await service.createBackup([makeEntry('e1')], 'wallet-001');
        expect(backup.encryptedData).toContain(':');
    });

    it('calls fetch when endpoint is configured', async () => {
        const fetchMock = vi.fn().mockResolvedValue({ ok: true });
        vi.stubGlobal('fetch', fetchMock);

        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
            endpoint: 'https://escrow.example.com/backups',
        });

        await service.createBackup([makeEntry('e1')], 'wallet-001');
        expect(fetchMock).toHaveBeenCalledOnce();
        expect(fetchMock).toHaveBeenCalledWith(
            'https://escrow.example.com/backups',
            expect.objectContaining({ method: 'POST' })
        );

        vi.unstubAllGlobals();
    });

    it('does not call fetch when no endpoint is configured', async () => {
        const fetchMock = vi.fn();
        vi.stubGlobal('fetch', fetchMock);

        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        await service.createBackup([makeEntry('e1')], 'wallet-001');
        expect(fetchMock).not.toHaveBeenCalled();

        vi.unstubAllGlobals();
    });
});

describe('EscrowBackupService.decryptBackup()', () => {
    it('round-trip: decrypted entries match original', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        const original = [makeEntry('e1'), makeEntry('e2'), makeEntry('e3')];
        const backup = await service.createBackup(original, 'wallet-001');
        const restored = await service.decryptBackup(backup, dpaKeyPair.privateKey);

        expect(restored).toHaveLength(original.length);
        expect(restored.map(e => e.id)).toEqual(original.map(e => e.id));
    });

    it('rejects when decrypted with a wrong private key', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        const wrongKeyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt']
        );

        const backup = await service.createBackup([makeEntry('e1')], 'wallet-001');
        await expect(service.decryptBackup(backup, wrongKeyPair.privateKey)).rejects.toThrow();
    });

    it('metadata firstEntry/lastEntry reflect entry timestamps', async () => {
        const service = new EscrowBackupService({
            dpaPublicKey: dpaKeyPair.publicKey,
            retentionDays: 30,
        });

        const entries = [
            { ...makeEntry('e1'), timestamp: '2025-01-01T00:00:00.000Z' },
            { ...makeEntry('e2'), timestamp: '2025-06-01T00:00:00.000Z' },
        ];

        const backup = await service.createBackup(entries, 'wallet-001');
        expect(backup.metadata.firstEntry).toBe('2025-01-01T00:00:00.000Z');
        expect(backup.metadata.lastEntry).toBe('2025-06-01T00:00:00.000Z');
    });
});
