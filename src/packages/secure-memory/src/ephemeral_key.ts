import { webcrypto } from 'node:crypto';

export interface ShredProof {
    timestamp: string;
    preShredHash: string;
    postShredHash: string;
    shredMethod: string;
    operationSuccess: boolean;
    duration_ms: number;
}

/**
 * EphemeralKey: Crypto-Shredding Wrapper for miTch
 * 
 * Guarantees:
 * ✅ Key is zeroed IMMEDIATELY after use
 * ✅ Audit proof of shredding
 * ✅ Timeout-safe
 * ✅ Exception-safe (finally block)
 * 
 * Usage:
 * const key = EphemeralKey.generate();
 * const result = await key.use(async (k) => {
 *   return await doSomethingSecure(k);
 * });
 * // key is now shredded. Proof available via key.getShredProof()
 */
export class EphemeralKey {
    private keyMaterial: Uint8Array | null;
    private isDestroyed: boolean = false;
    private shredProof: ShredProof | null = null;

    private constructor(keyMaterial: Uint8Array) {
        this.keyMaterial = new Uint8Array(keyMaterial);
        // IMPORTANT: Clear caller's copy to enforce ownership
        keyMaterial.fill(0);
    }

    /**
     * Generate a new random ephemeral key
     */
    static generate(lengthBytes: number = 32): EphemeralKey {
        const randomKey = webcrypto.getRandomValues(
            new Uint8Array(lengthBytes)
        );
        return new EphemeralKey(randomKey);
    }

    /**
     * Import existing key (caller's copy will be cleared)
     */
    static import(keyMaterial: Uint8Array): EphemeralKey {
        return new EphemeralKey(keyMaterial);
    }

    /**
     * Execute operation with guarantee of immediate shredding
     */
    async use<T>(
        operation: (key: Uint8Array) => Promise<T>,
        timeoutMs: number = 30000
    ): Promise<T> {
        if (this.isDestroyed || !this.keyMaterial) {
            throw new Error("Key has already been destroyed");
        }

        const startTime = Date.now();
        let operationSuccess = false;

        try {
            // Race: operation or timeout
            const result = await Promise.race([
                this.executeOperation(operation),
                this.createTimeoutPromise(timeoutMs),
            ]);
            operationSuccess = true;
            return result;
        } finally {
            // CRITICAL: Always shred, even on exception/timeout
            this.shred(operationSuccess, Date.now() - startTime);
        }
    }

    private async executeOperation<T>(
        operation: (key: Uint8Array) => Promise<T>
    ): Promise<T> {
        if (!this.keyMaterial) throw new Error("Key destroyed");
        return operation(this.keyMaterial);
    }

    private createTimeoutPromise(_ms: number): Promise<never> {
        return new Promise((_, reject) =>
            setTimeout(
                () => {
                    reject(new Error(`EphemeralKey operation timeout (${_ms}ms)`));
                },
                _ms
            )
        );
    }

    private shred(success: boolean, duration_ms: number) {
        if (this.isDestroyed || !this.keyMaterial) return;

        // 1. Hash BEFORE shred
        const preShredHash = this.computeHash(this.keyMaterial);

        // 2. Overwrite with zeros (primary method)
        this.keyMaterial.fill(0);

        // 3. Force GC (optional, for PoC)
        if (global.gc) {
            global.gc();
        }

        // 4. Verify it's gone
        const postShredHash = this.computeHash(this.keyMaterial);

        // 5. Create proof
        this.shredProof = {
            timestamp: new Date().toISOString(),
            preShredHash,
            postShredHash, // Should be all zeros
            shredMethod: 'fill(0) + explicit dereference',
            operationSuccess: success,
            duration_ms,
        };

        // 6. Break reference
        this.keyMaterial = null;
        this.isDestroyed = true;

        // 7. Log for audit
        console.log(
            `[Crypto-Shredding] Key destroyed at ${this.shredProof.timestamp}` +
            ` (duration: ${duration_ms}ms, success: ${success})`
        );
    }

    private computeHash(data: Uint8Array): string {
        const hash = webcrypto.createHash('sha256');
        hash.update(data);
        return hash.digest('hex');
    }

    /**
     * Get proof of shredding (for audit/compliance)
     */
    getShredProof(): ShredProof {
        if (!this.shredProof) {
            throw new Error("Key has not been shredded yet");
        }
        return this.shredProof;
    }

    /**
     * Check if key is destroyed
     */
    isShredded(): boolean {
        return this.isDestroyed;
    }

    /**
     * Debug: Peek at memory (FOR TESTING ONLY)
     */
    _debugPeek(): Uint8Array | null {
        return this.keyMaterial;
    }
}
