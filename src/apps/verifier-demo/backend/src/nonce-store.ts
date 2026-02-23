import fs from 'fs';

export interface NonceStoreOptions {
    ttlMs: number;
    maxEntries: number;
    cleanupIntervalMs?: number;
    persistencePath?: string;
}

interface PersistedState {
    version: 1;
    entries: Array<[string, number]>;
}

export class NonceStore {
    private entries = new Map<string, number>();
    private cleanupTimer?: ReturnType<typeof setInterval>;
    private saveScheduled = false;

    constructor(private options: NonceStoreOptions) {
        if (options.cleanupIntervalMs && options.cleanupIntervalMs > 0) {
            this.cleanupTimer = setInterval(() => this.cleanupExpired(), options.cleanupIntervalMs);
        }
    }

    loadFromDisk(): void {
        if (!this.options.persistencePath) return;
        if (!fs.existsSync(this.options.persistencePath)) return;

        try {
            const raw = fs.readFileSync(this.options.persistencePath, 'utf-8');
            const parsed = JSON.parse(raw) as PersistedState;
            if (parsed.version !== 1 || !Array.isArray(parsed.entries)) return;

            const now = Date.now();
            for (const [key, expiresAt] of parsed.entries) {
                if (typeof key !== 'string' || typeof expiresAt !== 'number') continue;
                if (expiresAt > now) {
                    this.entries.set(key, expiresAt);
                }
            }
        } catch {
            // Ignore corrupted cache files.
        }
    }

    has(key: string, now: number = Date.now()): boolean {
        const expiresAt = this.entries.get(key);
        if (expiresAt === undefined) return false;
        if (expiresAt <= now) {
            this.entries.delete(key);
            return false;
        }
        return true;
    }

    add(key: string, now: number = Date.now()): void {
        const expiresAt = now + this.options.ttlMs;
        this.entries.set(key, expiresAt);

        // T-40: Strict LRU Eviction
        if (this.entries.size > this.options.maxEntries) {
            const overflow = this.entries.size - this.options.maxEntries;
            // Map keys iterator is in insertion order (quasi-LRU if we re-insert on access/update)
            const iter = this.entries.keys();
            for (let i = 0; i < overflow; i++) {
                const result = iter.next();
                if (result.done) break;
                this.entries.delete(result.value);
            }
        }

        this.scheduleSave();
    }

    checkAndAdd(key: string, now: number = Date.now()): boolean {
        if (this.has(key, now)) return true;
        this.add(key, now);
        return false;
    }

    cleanupExpired(now: number = Date.now()): void {
        for (const [key, expiresAt] of this.entries) {
            if (expiresAt <= now) this.entries.delete(key);
        }
        this.scheduleSave();
    }

    flushToDisk(): void {
        if (!this.options.persistencePath) return;
        const state: PersistedState = {
            version: 1,
            entries: Array.from(this.entries.entries())
        };

        try {
            const tmpPath = `${this.options.persistencePath}.tmp`;
            fs.writeFileSync(tmpPath, JSON.stringify(state, null, 2));
            fs.renameSync(tmpPath, this.options.persistencePath);
        } catch {
            // Ignore disk write failures in demo environment.
        }
    }

    clear(): void {
        this.entries.clear();
        this.scheduleSave();
    }

    close(): void {
        if (this.cleanupTimer) clearInterval(this.cleanupTimer);
        this.flushToDisk();
    }

    private scheduleSave(): void {
        if (!this.options.persistencePath) return;
        if (this.saveScheduled) return;
        this.saveScheduled = true;
        setTimeout(() => {
            this.saveScheduled = false;
            this.flushToDisk();
        }, 250);
    }
}
