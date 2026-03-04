import { AuditLogEntry, AuditLogExport, L2AnchorReceipt } from '@mitch/shared-types';
import { sha256, signData, verifyData, canonicalStringify } from '@mitch/shared-crypto';
import { StateAnchorClient } from './anchor';
import { IndexedDBAuditStore } from './storage/indexeddb-store';
import { L2AnchorClient, type L2Network, type L2AnchorConfig } from './storage/l2-anchor-client';
import { EscrowBackupService, type EscrowConfig } from './storage/escrow-backup';
export * from './verify';
export * from './storage';


/**
 * Audit-Grade Tamper-evident Log for miTch.
 * 
 * Implements H1-H5 Hardening:
 * - H1: Canonical JSON stringification for stable hashing
 * - H2: Signing canonical bytes of the entry
 * - H3: Explicit sigAlg, kid, and versioning
 * - H4: Enforced signature checks if public key is present
 * - H5: Report-level signature to prevent entry cherry-picking
 * - T-28: L2 Anchoring for non-repudiation
 */
export class AuditLog {
    private entries: AuditLogEntry[] = [];
    private anchors: L2AnchorReceipt[] = [];
    private auditPrivateKey: CryptoKey | null = null;
    private auditPublicKey: CryptoKey | null = null;
    private kid: string = 'audit-key-2026-v1';

    // Production-Grade Storage Layers
    private persistentStore?: IndexedDBAuditStore;
    private l2Client?: L2AnchorClient;
    private escrowService?: EscrowBackupService;
    private useProductionStorage: boolean = false;

    constructor(
        private walletId: string,
        options?: {
            useProductionStorage?: boolean;
            l2Config?: L2AnchorConfig;
            escrowConfig?: EscrowConfig;
        }
    ) {
        this.useProductionStorage = options?.useProductionStorage ?? false;

        if (this.useProductionStorage) {
            // Initialize production storage layers
            this.persistentStore = new IndexedDBAuditStore(walletId);

            if (options?.l2Config) {
                this.l2Client = new L2AnchorClient(options.l2Config);
            }

            if (options?.escrowConfig) {
                this.escrowService = new EscrowBackupService(options.escrowConfig);
            }
        }
    }

    /**
     * Initialize production storage (must be called after construction)
     */
    async initialize(): Promise<void> {
        if (this.useProductionStorage && this.persistentStore) {
            await this.persistentStore.initialize();

            // Load existing entries from IndexedDB
            const storedEntries = await this.persistentStore.getAllEntries();
            this.entries = storedEntries;

            console.info(`[AuditLog] Loaded ${this.entries.length} entries from persistent storage`);
        }
    }


    /**
     * Set the keys used for signing the audit trail.
     */
    setAuditKeys(privateKey: CryptoKey, publicKey: CryptoKey, kid?: string) {
        this.auditPrivateKey = privateKey;
        this.auditPublicKey = publicKey;
        if (kid) this.kid = kid;
    }

    /**
     * Append a new entry to the immutable log.
     */
    async append(
        action: AuditLogEntry['action'],
        subjectId?: string,
        metadata?: Record<string, unknown>
    ): Promise<AuditLogEntry> {
        const previousHash = this.entries.length > 0
            ? this.entries[this.entries.length - 1].currentHash
            : '0'.repeat(64);

        const entry: AuditLogEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            action,
            subjectId,
            previousHash,
            metadata,
            currentHash: '',
            version: '2.0',
            sigAlg: 'ECDSA_P256_SHA256',
            kid: this.kid
        };

        const payloadToSign = {
            id: entry.id,
            timestamp: entry.timestamp,
            action: entry.action,
            subjectId: entry.subjectId,
            previousHash: entry.previousHash,
            metadata: entry.metadata,
            version: entry.version,
            sigAlg: entry.sigAlg,
            kid: entry.kid
        };
        const dataToHash = canonicalStringify(payloadToSign);
        entry.currentHash = await sha256(dataToHash);

        if (this.auditPrivateKey) {
            entry.signature = await signData(dataToHash, this.auditPrivateKey);
        }

        this.entries.push(entry);

        // Persist to IndexedDB if production storage is enabled
        if (this.useProductionStorage && this.persistentStore) {
            try {
                await this.persistentStore.append(entry);
            } catch (error) {
                console.error('[AuditLog] Failed to persist entry:', error);
                // Continue anyway - in-memory log is still valid
            }
        }

        // Create escrow backup periodically (every 100 entries)
        if (this.useProductionStorage && this.escrowService && this.entries.length % 100 === 0) {
            try {
                await this.escrowService.createBackup(this.entries, this.walletId);
                console.info(`[AuditLog] Created escrow backup at ${this.entries.length} entries`);
            } catch (error) {
                console.error('[AuditLog] Failed to create escrow backup:', error);
            }
        }

        return entry;
    }


    /**
     * Anchor the current state root to Layer 2 (T-28).
     */
    async syncToL2(): Promise<L2AnchorReceipt> {
        // Calculate report hash (State Root)
        const entriesCanonical = canonicalStringify(this.entries.map(e => ({
            id: e.id,
            hash: e.currentHash,
            sig: e.signature
        })));
        const stateRoot = await sha256(entriesCanonical);

        // Use production L2 client if available
        let receipt: L2AnchorReceipt;
        if (this.useProductionStorage && this.l2Client) {
            receipt = await this.l2Client.anchorRoot(stateRoot);
        } else {
            // Fallback to mock for development
            receipt = await StateAnchorClient.anchorRoot(stateRoot);
        }

        this.anchors.push(receipt);

        await this.append('POLICY_EVALUATED', 'l2-anchor-sync', {
            txId: receipt.l2TransactionId,
            root: stateRoot
        });

        return receipt;
    }


    /**
     * Verify the entire chain's integrity and authenticity.
     */
    async verifyChain(): Promise<{ valid: boolean; error?: string; brokenIndex?: number }> {
        for (let i = 0; i < this.entries.length; i++) {
            const entry = this.entries[i];
            const prevHash = i > 0 ? this.entries[i - 1].currentHash : '0'.repeat(64);

            if (entry.previousHash !== prevHash) {
                return { valid: false, error: 'Hash chain link broken', brokenIndex: i };
            }

            const dataToHash = canonicalStringify({
                id: entry.id,
                timestamp: entry.timestamp,
                action: entry.action,
                subjectId: entry.subjectId,
                previousHash: entry.previousHash,
                metadata: entry.metadata,
                version: entry.version,
                sigAlg: entry.sigAlg,
                kid: entry.kid
            });
            const computedHash = await sha256(dataToHash);
            if (computedHash !== entry.currentHash) {
                return { valid: false, error: 'Entry content corrupted or non-canonical', brokenIndex: i };
            }

            if (this.auditPublicKey) {
                if (!entry.signature) {
                    return { valid: false, error: 'SECURITY VIOLATION: Missing signature', brokenIndex: i };
                }
                const isAuthentic = await verifyData(dataToHash, entry.signature, this.auditPublicKey);
                if (!isAuthentic) {
                    return { valid: false, error: 'Signature invalid', brokenIndex: i };
                }
            }
        }
        return { valid: true };
    }

    /**
     * Export a GDPR-ready report with L2 Evidence.
     */
    async exportReport(): Promise<AuditLogExport> {
        const integrity = await this.verifyChain();

        const shredEvents = this.entries.filter(e => e.action === 'KEY_DESTROYED');
        const createEvents = this.entries.filter(e => e.action === 'KEY_CREATED');

        let totalLatency = 0;
        let latencyCount = 0;

        shredEvents.forEach(s => {
            const dId = s.metadata?.decision_id;
            if (dId) {
                const birth = createEvents.find(c => c.metadata?.decision_id === dId);
                if (birth) {
                    const diff = new Date(s.timestamp).getTime() - new Date(birth.timestamp).getTime();
                    totalLatency += diff;
                    latencyCount++;
                }
            }
        });

        const complianceSummary: NonNullable<AuditLogExport['complianceSummary']> = {
            totalEvents: this.entries.length,
            shreddingCount: shredEvents.length,
            dataMinimizationEvents: this.entries.filter(e => e.action === 'VP_GENERATED').length,
            averageShreddingLatencyMs: latencyCount > 0 ? Math.round(totalLatency / latencyCount) : 0,
            policyComplianceStatus: integrity.valid ? 'EXCELLENT' : 'ATTENTION'
        };

        const entriesCanonical = canonicalStringify(this.entries.map(e => ({
            id: e.id,
            hash: e.currentHash,
            sig: e.signature
        })));
        const reportHash = await sha256(entriesCanonical);

        const report: AuditLogExport = {
            version: '2.0',
            exportedAt: new Date().toISOString(),
            owner: `did:mitch:${this.walletId}`,
            entries: [...this.entries],
            chainIntegrity: {
                valid: integrity.valid,
                brokenAtIndex: integrity.brokenIndex
            },
            complianceSummary,
            anchors: [...this.anchors],
            reportHash
        };

        if (this.auditPrivateKey) {
            report.signature = await signData(reportHash, this.auditPrivateKey);
        }

        return report;
    }

    getRecentEntries(limit: number = 10): AuditLogEntry[] {
        return [...this.entries].reverse().slice(0, limit);
    }

    getShreddingReceipt(keyId: string): AuditLogEntry | undefined {
        return this.entries.find(e => e.action === 'KEY_DESTROYED' && e.subjectId === keyId);
    }

    getShreddingCertificateByDecision(decisionId: string): AuditLogEntry[] {
        return this.entries.filter(e =>
            e.action === 'KEY_DESTROYED' &&
            e.metadata?.decision_id === decisionId
        );
    }

    /**
     * Cleanup storage connections
     */
    async cleanup(): Promise<void> {
        if (this.persistentStore) {
            this.persistentStore.close();
        }

        if (this.l2Client) {
            this.l2Client.stopBatchTimer();
        }
    }
}

