/**
 * Local Audit Log (Phase-0 Security)
 * 
 * Implements a tamper-evident, hash-chained audit log stored in IndexedDB.
 * This ensures "User Custody" - the user holds their own audit history, not the server.
 * 
 * Features:
 * - IndexedDB Storage (mitch-audit-log)
 * - SHA-256 Hash Chaining (prevHash + content)
 * - Tamper Evidence Verification
 */

export interface LogEntry {
    timestamp: number;
    action: string;
    verifier?: string;
    verdict?: 'ALLOW' | 'DENY' | 'PROMPT';
    details?: any;
}

export interface ChainedEntry extends LogEntry {
    sequence: number;
    prevHash: string;
    hash: string;
}

interface EncryptedChainedEntry {
    sequence: number;
    prevHash: string;
    hash: string;
    iv: string;         // Hex encoded IV
    ciphertext: string; // Hex encoded encrypted payload
}

export class LocalAuditLog {
    private dbName = 'mitch-audit-log';
    private storeName = 'entries';
    private db: IDBDatabase | null = null;
    private encryptionKey: CryptoKey | null = null;

    constructor() { }

    async initialize(): Promise<void> {
        if (this.db && this.encryptionKey) return;

        // 1. Generate Session Encryption Key (AES-GCM-256)
        // Non-extractable = Structural Non-Existence (Key dies with RAM)
        if (!this.encryptionKey) {
            this.encryptionKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                false, // NON-EXTRACTABLE
                ['encrypt', 'decrypt']
            );
        }

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, 1);

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    const store = db.createObjectStore(this.storeName, { keyPath: 'sequence' });
                    store.createIndex('hash', 'hash', { unique: true });
                }
            };

            request.onsuccess = (event) => {
                this.db = (event.target as IDBOpenDBRequest).result;
                resolve();
            };

            request.onerror = (event) => {
                console.error('AuditLog DB Error:', event);
                reject('Failed to open audit log database');
            };
        });
    }

    async append(entry: LogEntry): Promise<ChainedEntry> {
        if (!this.db || !this.encryptionKey) await this.initialize();

        const lastEntry = await this.getLastEntry();
        const sequence = (lastEntry?.sequence ?? 0) + 1;
        const prevHash = lastEntry?.hash ?? 'GENESIS_HASH'; // Structural Non-Existence anchor

        const chained: ChainedEntry = {
            ...entry,
            sequence,
            prevHash,
            hash: '' // Calculated below
        };

        // 1. Compute Hash on CLEARTEXT (Canonical)
        // We hash the cleartext to ensure the chain represents the actual events.
        chained.hash = await this.computeHash(chained);

        // 2. Encrypt the payload
        // We encrypt the sensitive parts: timestamp, action, verifier, verdict, details.
        // Sequence, prevHash, hash remain plaintext for chain traversal (but hash protects integrity).
        const payload = JSON.stringify({
            timestamp: chained.timestamp,
            action: chained.action,
            verifier: chained.verifier,
            verdict: chained.verdict,
            details: chained.details
        });

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(payload);

        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.encryptionKey!,
            encoded
        );

        const storedObject: EncryptedChainedEntry = {
            sequence: chained.sequence,
            prevHash: chained.prevHash,
            hash: chained.hash,
            iv: this.bufferToHex(iv.buffer as ArrayBuffer),
            ciphertext: this.bufferToHex(encryptedBuffer)
        };

        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(this.storeName, 'readwrite');
            const store = tx.objectStore(this.storeName);
            const req = store.add(storedObject);

            req.onsuccess = () => resolve(chained);
            req.onerror = () => reject('Failed to write audit entry');
        });
    }

    async verifyIntegrity(): Promise<{ valid: boolean; brokenSequence?: number }> {
        if (!this.db || !this.encryptionKey) await this.initialize();

        const entries = await this.getAllEntries();
        if (entries.length === 0) return { valid: true };

        let prevHash = 'GENESIS_HASH';

        for (const entry of entries) {
            if (entry.prevHash !== prevHash) {
                return { valid: false, brokenSequence: entry.sequence };
            }

            const computed = await this.computeHash(entry);
            if (computed !== entry.hash) {
                return { valid: false, brokenSequence: entry.sequence };
            }

            prevHash = entry.hash;
        }

        return { valid: true };
    }

    async getAllEntries(): Promise<ChainedEntry[]> {
        if (!this.db || !this.encryptionKey) await this.initialize();
        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(this.storeName, 'readonly');
            const store = tx.objectStore(this.storeName);
            const req = store.getAll();
            req.onsuccess = async () => {
                const storedItems = req.result as EncryptedChainedEntry[];
                storedItems.sort((a, b) => a.sequence - b.sequence);

                const decryptedItems: ChainedEntry[] = [];
                try {
                    for (const item of storedItems) {
                        try {
                            const iv = this.hexToBuffer(item.iv);
                            const ciphertext = this.hexToBuffer(item.ciphertext);

                            const decryptedBuffer = await crypto.subtle.decrypt(
                                { name: 'AES-GCM', iv: iv as BufferSource },
                                this.encryptionKey!,
                                ciphertext as BufferSource
                            );

                            const payload = JSON.parse(new TextDecoder().decode(decryptedBuffer));

                            decryptedItems.push({
                                sequence: item.sequence,
                                prevHash: item.prevHash,
                                hash: item.hash,
                                ...payload
                            });
                        } catch (decryptErr) {
                            console.warn(`[Audit] Failed to decrypt entry ${item.sequence}:`, decryptErr);
                            // Push placeholder entry (Integrity preserved via hash chain, content lost)
                            decryptedItems.push({
                                sequence: item.sequence,
                                prevHash: item.prevHash,
                                hash: item.hash,
                                timestamp: 0,
                                action: '[ENCRYPTED - KEY LOST]',
                                verifier: 'UNKNOWN',
                                verdict: undefined,
                                details: { error: 'Decryption failed: Key mismatch or missing' }
                            } as ChainedEntry);
                        }
                    }
                    resolve(decryptedItems);
                } catch (e) {
                    console.error('Fatal error processing audit log:', e);
                    resolve([]);
                }
            };
            req.onerror = () => reject('Failed to read entries');
        });
    }

    private async getLastEntry(): Promise<ChainedEntry | null> {
        // Optimization: We don't need to decrypt everything just to get the last hash/sequence.
        // We can peek at the last stored object directly.
        if (!this.db) await this.initialize();

        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(this.storeName, 'readonly');
            const store = tx.objectStore(this.storeName);
            const req = store.openCursor(null, 'prev'); // Get last element

            req.onsuccess = (event) => {
                const cursor = (event.target as IDBRequest).result as IDBCursorWithValue;
                if (cursor) {
                    const stored = cursor.value as EncryptedChainedEntry;
                    // We only need sequence and hash for chaining, no decryption needed here!
                    // But strictly speaking, the return type is ChainedEntry which has payload fields.
                    // For 'getLastEntry' usage in append, we only use sequence and hash.
                    // IMPORTANT: We return a partial object cast as ChainedEntry to satisfy type, 
                    // knowing that append ONLY reads sequence and hash.
                    resolve({
                        sequence: stored.sequence,
                        hash: stored.hash,
                        prevHash: stored.prevHash,
                        timestamp: 0, action: '', // Dummy values
                    } as ChainedEntry);
                } else {
                    resolve(null);
                }
            };
            req.onerror = () => reject('Failed to get last entry');
        });
    }

    private async computeHash(entry: ChainedEntry): Promise<string> {
        // Canonicalize by excluding hash and sorting keys (simple JSON for Phase-0)
        const data = {
            sequence: entry.sequence,
            prevHash: entry.prevHash,
            timestamp: entry.timestamp,
            action: entry.action,
            verifier: entry.verifier,
            verdict: entry.verdict,
            details: entry.details
        };

        const json = JSON.stringify(data);
        const msgBuffer = new TextEncoder().encode(json);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return this.bufferToHex(hashBuffer);
    }

    private bufferToHex(buffer: ArrayBuffer): string {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    private hexToBuffer(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }

    // GDPR Art. 20 - Data Portability / Export
    async exportForUser(): Promise<{
        entries: ChainedEntry[];
        integrityProof: {
            rootHash: string;
            totalEntries: number;
            firstTimestamp: number;
            lastTimestamp: number;
        };
    }> {
        const entries = await this.getAllEntries();
        const lastEntry = entries[entries.length - 1];

        return {
            entries,
            integrityProof: {
                rootHash: lastEntry?.hash || 'GENESIS_HASH',
                totalEntries: entries.length,
                firstTimestamp: entries[0]?.timestamp || 0,
                lastTimestamp: lastEntry?.timestamp || 0
            }
        };
    }

    // GDPR Art. 17 - Right to Erasure
    async deleteAll(): Promise<void> {
        if (!this.db) await this.initialize();

        return new Promise((resolve, reject) => {
            const tx = this.db!.transaction(this.storeName, 'readwrite');
            const store = tx.objectStore(this.storeName);
            const req = store.clear();

            req.onsuccess = () => {
                console.warn('[Audit] ALL ENTRIES DELETED by user (GDPR Art. 17)');
                resolve();
            };
            req.onerror = () => reject('Failed to delete entries');
        });
    }
}
