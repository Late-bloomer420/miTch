/**
 * Local Audit-Log with Hash-Chain (WORM - Write-Once-Read-Many)
 * 
 * COMPLIANCE:
 * - DSGVO Art. 30: Verzeichnis von Verarbeitungstätigkeiten (User-Custody)
 * - eIDAS 2.0 Art. 6a(5): Wallet Audit-Logs für Nutzer zugänglich
 * - NIS2 Art. 21: Sicherheitsprotokolle für Incident Response
 * 
 * SECURITY:
 * - Tamper-evident: SHA-256 Hash-Chain
 * - Encrypted: AES-GCM with ephemeral session key
 * - Non-extractable: Key lives only in WebCrypto (RAM)
 * - Integrity-verifiable: Full chain validation
 */

export interface AuditEvent {
  type: 
    | 'CREDENTIAL_ISSUED'
    | 'CREDENTIAL_PRESENTED'
    | 'POLICY_EVALUATED'
    | 'KEY_GENERATED'
    | 'KEY_DESTROYED'
    | 'HUMAN_VERIFICATION'
    | 'AUTOMATION_BLOCKED';
  timestamp: number;
  details: Record<string, any>;
}

interface AuditEntry {
  id: string; // SHA-256 hash (serves as primary key)
  timestamp: number;
  type: string;
  encrypted_data: ArrayBuffer;
  iv: Uint8Array;
  hash: string;
  prev_hash: string;
}

interface ExportedLog {
  entries: AuditEvent[];
  integrityProof: {
    rootHash: string;
    totalEntries: number;
    firstTimestamp: number;
    lastTimestamp: number;
  };
}

export class LocalAuditLog {
  private db: IDBDatabase | null = null;
  private encryptionKey: CryptoKey | null = null;
  private currentHash: string = '0'.repeat(64); // Genesis hash
  private readonly DB_NAME = 'mitch-audit-log';
  private readonly STORE_NAME = 'audit_events';
  private readonly DB_VERSION = 1;

  /**
   * Initialize audit-log with ephemeral encryption key
   */
  async initialize(): Promise<void> {
    // 1. Open IndexedDB (browser-based storage)
    this.db = await this.openDatabase();
    
    // 2. Generate ephemeral encryption key (SESSION-SCOPED, non-extractable)
    this.encryptionKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // NON-EXTRACTABLE (cannot be exported)
      ['encrypt', 'decrypt']
    );
    
    // 3. Load latest hash from chain
    const latestEntry = await this.getLatestEntry();
    if (latestEntry) {
      this.currentHash = latestEntry.hash;
    }
    
    console.info('[Audit] Initialized. Current hash:', this.currentHash.slice(0, 16) + '...');
  }

  /**
   * Append event to audit-log (WORM - Write-Once)
   * Creates tamper-evident hash-chain
   */
  async append(event: AuditEvent): Promise<void> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Audit-log not initialized');
    }

    // 1. Add timestamp if not present
    if (!event.timestamp) {
      event.timestamp = Date.now();
    }

    // 2. Serialize event
    const eventJson = JSON.stringify(event);
    const eventBytes = new TextEncoder().encode(eventJson);

    // 3. Compute hash (current event + previous hash = chain)
    const dataToHash = eventJson + this.currentHash;
    const hashBuffer = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(dataToHash)
    );
    const newHash = this.bufferToHex(hashBuffer);

    // 4. Encrypt event data (AES-GCM with random IV)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.encryptionKey,
      eventBytes
    );

    // 5. Store in IndexedDB (immutable - no UPDATE allowed)
    const entry: AuditEntry = {
      id: newHash, // Hash serves as primary key
      timestamp: event.timestamp,
      type: event.type,
      encrypted_data: ciphertext,
      iv: iv,
      hash: newHash,
      prev_hash: this.currentHash
    };

    const tx = this.db.transaction(this.STORE_NAME, 'readwrite');
    const store = tx.objectStore(this.STORE_NAME);
    
    await new Promise<void>((resolve, reject) => {
      const request = store.add(entry);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });

    // 6. Update current hash (advance chain)
    this.currentHash = newHash;

    console.info(
      `[Audit] Logged: ${event.type} at ${new Date(event.timestamp).toISOString()} ` +
      `(hash: ${newHash.slice(0, 8)}...)`
    );
  }

  /**
   * Verify integrity of entire hash-chain
   * Returns false if ANY entry was tampered with
   */
  async verifyIntegrity(): Promise<boolean> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Audit-log not initialized');
    }

    const tx = this.db.transaction(this.STORE_NAME, 'readonly');
    const store = tx.objectStore(this.STORE_NAME);
    
    const entries = await new Promise<AuditEntry[]>((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    // Sort by timestamp (chain order)
    entries.sort((a, b) => a.timestamp - b.timestamp);

    let prevHash = '0'.repeat(64); // Genesis
    let tamperedCount = 0;

    for (const entry of entries) {
      // Decrypt event data
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: entry.iv },
        this.encryptionKey,
        entry.encrypted_data
      );
      const eventJson = new TextDecoder().decode(decrypted);

      // Recompute hash
      const dataToHash = eventJson + prevHash;
      const hashBuffer = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(dataToHash)
      );
      const computedHash = this.bufferToHex(hashBuffer);

      // Check integrity
      if (computedHash !== entry.hash) {
        console.error(
          `[Audit] INTEGRITY VIOLATION at ${new Date(entry.timestamp).toISOString()}:\n` +
          `Expected: ${entry.hash}\n` +
          `Computed: ${computedHash}`
        );
        tamperedCount++;
      }

      if (entry.prev_hash !== prevHash) {
        console.error(
          `[Audit] CHAIN BREAK at ${new Date(entry.timestamp).toISOString()}:\n` +
          `Expected prev_hash: ${prevHash}\n` +
          `Actual prev_hash: ${entry.prev_hash}`
        );
        tamperedCount++;
      }

      prevHash = entry.hash;
    }

    if (tamperedCount > 0) {
      console.error(`[Audit] Integrity check FAILED: ${tamperedCount} violations detected`);
      return false;
    }

    console.info(`[Audit] Integrity verified ✓ (${entries.length} entries, chain intact)`);
    return true;
  }

  /**
   * Export log for user (GDPR Art. 20 - Data Portability)
   */
  async exportForUser(): Promise<ExportedLog> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Audit-log not initialized');
    }

    const tx = this.db.transaction(this.STORE_NAME, 'readonly');
    const store = tx.objectStore(this.STORE_NAME);
    
    const entries = await new Promise<AuditEntry[]>((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    entries.sort((a, b) => a.timestamp - b.timestamp);

    // Decrypt all entries
    const decryptedEvents: AuditEvent[] = [];
    for (const entry of entries) {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: entry.iv },
        this.encryptionKey,
        entry.encrypted_data
      );
      const event = JSON.parse(new TextDecoder().decode(decrypted));
      decryptedEvents.push(event);
    }

    return {
      entries: decryptedEvents,
      integrityProof: {
        rootHash: this.currentHash,
        totalEntries: entries.length,
        firstTimestamp: entries[0]?.timestamp || 0,
        lastTimestamp: entries[entries.length - 1]?.timestamp || 0
      }
    };
  }

  /**
   * Delete entire log (GDPR Art. 17 - Right to Erasure)
   */
  async deleteAll(): Promise<void> {
    if (!this.db) {
      throw new Error('Audit-log not initialized');
    }

    const tx = this.db.transaction(this.STORE_NAME, 'readwrite');
    const store = tx.objectStore(this.STORE_NAME);
    
    await new Promise<void>((resolve, reject) => {
      const request = store.clear();
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });

    // Reset chain
    this.currentHash = '0'.repeat(64);
    
    console.warn('[Audit] ALL ENTRIES DELETED by user (GDPR Art. 17)');
  }

  /**
   * Get count of log entries
   */
  async getCount(): Promise<number> {
    if (!this.db) {
      throw new Error('Audit-log not initialized');
    }

    const tx = this.db.transaction(this.STORE_NAME, 'readonly');
    const store = tx.objectStore(this.STORE_NAME);
    
    return new Promise((resolve, reject) => {
      const request = store.count();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  // ==================== PRIVATE HELPERS ====================

  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains(this.STORE_NAME)) {
          const store = db.createObjectStore(this.STORE_NAME, { keyPath: 'id' });
          store.createIndex('timestamp', 'timestamp', { unique: false });
          store.createIndex('type', 'type', { unique: false });
        }
      };
    });
  }

  private async getLatestEntry(): Promise<AuditEntry | null> {
    if (!this.db) return null;

    const tx = this.db.transaction(this.STORE_NAME, 'readonly');
    const store = tx.objectStore(this.STORE_NAME);
    const index = store.index('timestamp');
    
    return new Promise((resolve, reject) => {
      const request = index.openCursor(null, 'prev'); // Reverse order
      request.onsuccess = () => {
        const cursor = request.result;
        resolve(cursor ? cursor.value : null);
      };
      request.onerror = () => reject(request.error);
    });
  }

  private bufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
