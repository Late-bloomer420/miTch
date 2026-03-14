import type { IEphemeralKey } from './interfaces/IEphemeralKey';

/**
 * EphemeralKey: Crypto-Shredding Primitive (Uint8Array variant)
 *
 * Wraps raw key bytes and zeroes them on shred(). Used by pairwise-did.ts
 * because raw byte shredding (fill(0)) is stronger than CryptoKey GC-based
 * destruction — the caller controls when bytes are overwritten.
 */
export class EphemeralKey implements IEphemeralKey {
    private keyData: Uint8Array | null;

    constructor(keyData: Uint8Array) {
        this.keyData = keyData;
    }

    getKey(): Uint8Array {
        if (!this.keyData) {
            throw new Error('Key has been shredded');
        }
        return this.keyData;
    }

    /**
     * Securely destroys the key material by overwriting with zeros.
     * This is the core "forgetting" mechanism.
     */
    shred(): void {
        if (this.keyData) {
            this.keyData.fill(0);
            this.keyData = null;
        }
    }

    isShredded(): boolean {
        return this.keyData === null;
    }
}
