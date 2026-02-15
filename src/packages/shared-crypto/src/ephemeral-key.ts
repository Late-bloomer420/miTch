/**
 * EphemeralKey: Crypto-Shredding Primitive
 * Represents a cryptographic key that can be securely destroyed.
 */
export class EphemeralKey {
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
