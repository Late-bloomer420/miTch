import { AuditLogEntry } from '@mitch/shared-types';

/**
 * Encrypted Escrow Backup Service
 * 
 * GDPR Compliance:
 * - Art. 32 DSGVO: Secure backup for disaster recovery
 * - DPA-accessible audit trail (with proper authorization)
 * - End-to-end encryption with key escrow
 * 
 * Architecture:
 * - User data encrypted with ephemeral key
 * - Ephemeral key encrypted with DPA public key
 * - Only DPA can decrypt for audits
 * - 7-year retention (GDPR statute of limitations)
 */

export interface EscrowConfig {
    dpaPublicKey: CryptoKey;  // DPA's RSA public key
    retentionDays: number;    // Default: 2555 days (7 years)
    endpoint?: string;        // Backup service endpoint
}

export interface EncryptedBackup {
    backupId: string;
    walletId: string;
    encryptedData: string;     // Base64-encoded encrypted audit log
    encryptedKey: string;      // Ephemeral key encrypted with DPA key
    createdAt: string;
    expiresAt: string;
    metadata: {
        entryCount: number;
        firstEntry: string;    // Timestamp
        lastEntry: string;     // Timestamp
    };
}

/**
 * Escrow Service for DPA-Accessible Audit Backups
 * 
 * Features:
 * - End-to-end encryption
 * - DPA-only decryption
 * - Automatic expiration
 * - Tamper-evident storage
 */
export class EscrowBackupService {
    private config: EscrowConfig;

    constructor(config: EscrowConfig) {
        this.config = config;
    }

    /**
     * Create an encrypted backup of audit log entries
     * 
     * @param entries - Audit log entries to backup
     * @param walletId - Wallet identifier
     */
    async createBackup(
        entries: AuditLogEntry[],
        walletId: string
    ): Promise<EncryptedBackup> {
        if (entries.length === 0) {
            throw new Error('Cannot create backup of empty audit log');
        }

        // 1. Generate ephemeral encryption key (AES-256)
        const ephemeralKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,  // extractable
            ['encrypt', 'decrypt']
        );

        // 2. Encrypt audit log entries
        const entriesJson = JSON.stringify(entries);
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            ephemeralKey,
            new TextEncoder().encode(entriesJson)
        );

        // 3. Export ephemeral key
        const exportedKey = await crypto.subtle.exportKey('raw', ephemeralKey);

        // 4. Encrypt ephemeral key with DPA public key
        const encryptedKey = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            this.config.dpaPublicKey,
            exportedKey
        );

        // 5. Create backup metadata
        const timestamps = entries.map(e => e.timestamp).sort();
        const createdAt = new Date().toISOString();
        const expiresAt = new Date(
            Date.now() + this.config.retentionDays * 24 * 60 * 60 * 1000
        ).toISOString();

        const backup: EncryptedBackup = {
            backupId: crypto.randomUUID(),
            walletId,
            encryptedData: this.arrayBufferToBase64(encryptedData),
            encryptedKey: this.arrayBufferToBase64(encryptedKey),
            createdAt,
            expiresAt,
            metadata: {
                entryCount: entries.length,
                firstEntry: timestamps[0],
                lastEntry: timestamps[timestamps.length - 1]
            }
        };

        // 6. Store IV alongside encrypted data (prepend)
        const ivBase64 = this.arrayBufferToBase64(iv);
        backup.encryptedData = `${ivBase64}:${backup.encryptedData}`;

        // 7. Upload to escrow service (if configured)
        if (this.config.endpoint) {
            await this.uploadBackup(backup);
        }

        return backup;
    }

    /**
     * Upload encrypted backup to escrow service
     */
    private async uploadBackup(backup: EncryptedBackup): Promise<void> {
        if (!this.config.endpoint) {
            console.warn('[EscrowBackup] No endpoint configured, skipping upload');
            return;
        }

        try {
            const response = await fetch(this.config.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Backup-Version': '1.0'
                },
                body: JSON.stringify(backup)
            });

            if (!response.ok) {
                throw new Error(`Upload failed: ${response.statusText}`);
            }

            console.info(`[EscrowBackup] Uploaded backup ${backup.backupId}`);
        } catch (error) {
            console.error('[EscrowBackup] Upload failed:', error);
            throw new Error('Failed to upload backup to escrow service');
        }
    }

    /**
     * Retrieve a backup from escrow service
     * 
     * NOTE: This is for DPA use only. User cannot decrypt without DPA private key.
     */
    async retrieveBackup(backupId: string): Promise<EncryptedBackup> {
        if (!this.config.endpoint) {
            throw new Error('No escrow endpoint configured');
        }

        const response = await fetch(`${this.config.endpoint}/${backupId}`, {
            method: 'GET',
            headers: {
                'X-Backup-Version': '1.0'
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to retrieve backup: ${response.statusText}`);
        }

        return await response.json();
    }

    /**
     * Decrypt a backup (DPA use only - requires DPA private key)
     * 
     * @param backup - Encrypted backup
     * @param dpaPrivateKey - DPA's RSA private key
     */
    async decryptBackup(
        backup: EncryptedBackup,
        dpaPrivateKey: CryptoKey
    ): Promise<AuditLogEntry[]> {
        // 1. Extract IV from encrypted data
        const [ivBase64, encryptedDataBase64] = backup.encryptedData.split(':');
        const iv = this.base64ToArrayBuffer(ivBase64);
        const encryptedData = this.base64ToArrayBuffer(encryptedDataBase64);
        const encryptedKey = this.base64ToArrayBuffer(backup.encryptedKey);

        // 2. Decrypt ephemeral key with DPA private key
        const decryptedKeyBuffer = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            dpaPrivateKey,
            encryptedKey
        );

        // 3. Import ephemeral key
        const ephemeralKey = await crypto.subtle.importKey(
            'raw',
            decryptedKeyBuffer,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // 4. Decrypt audit log entries
        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            ephemeralKey,
            encryptedData
        );

        // 5. Parse JSON
        const entriesJson = new TextDecoder().decode(decryptedData);
        return JSON.parse(entriesJson);
    }

    /**
     * List all backups for a wallet
     */
    async listBackups(walletId: string): Promise<EncryptedBackup[]> {
        if (!this.config.endpoint) {
            throw new Error('No escrow endpoint configured');
        }

        const response = await fetch(`${this.config.endpoint}/list/${walletId}`, {
            method: 'GET',
            headers: {
                'X-Backup-Version': '1.0'
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to list backups: ${response.statusText}`);
        }

        return await response.json();
    }

    /**
     * Delete expired backups (automatic cleanup)
     */
    async deleteExpiredBackups(walletId: string): Promise<number> {
        const backups = await this.listBackups(walletId);
        const now = new Date().toISOString();

        let deletedCount = 0;

        for (const backup of backups) {
            if (backup.expiresAt < now) {
                await this.deleteBackup(backup.backupId);
                deletedCount++;
            }
        }

        return deletedCount;
    }

    /**
     * Delete a specific backup
     */
    private async deleteBackup(backupId: string): Promise<void> {
        if (!this.config.endpoint) {
            return;
        }

        const response = await fetch(`${this.config.endpoint}/${backupId}`, {
            method: 'DELETE',
            headers: {
                'X-Backup-Version': '1.0'
            }
        });

        if (!response.ok) {
            console.error(`[EscrowBackup] Failed to delete backup ${backupId}`);
        }
    }

    // Utility methods

    private arrayBufferToBase64(buffer: ArrayBuffer | ArrayBufferView): string {
        const bytes = buffer instanceof ArrayBuffer
            ? new Uint8Array(buffer)
            : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}
