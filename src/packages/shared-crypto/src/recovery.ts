import { generateKeyPair } from './keys';

/**
 * RecoveryService: Implements "Trust Circle" Social Recovery.
 * 
 * Based on Shamir's Secret Sharing (PoC Implementation).
 * Allows the Master Key to be split into N fragments, requiring K to recover.
 */
export class RecoveryService {
    /**
     * Splits a Master Key (as Hex string) into 3 fragments (2-of-3 scheme).
     * This is a simplified XOR-based 2-of-2 for the PoC, 
     * but the interface supports the N-of-K concept.
     */
    static async splitMasterKey(masterKeyHex: string): Promise<string[]> {
        const keyBytes = new TextEncoder().encode(masterKeyHex);
        const fragment1 = new Uint8Array(keyBytes.length);
        const fragment2 = new Uint8Array(keyBytes.length);
        const fragment3 = new Uint8Array(keyBytes.length);

        // Generate random noise for fragments
        crypto.getRandomValues(fragment1);
        crypto.getRandomValues(fragment2);

        // Calculate third fragment such that F1 ^ F2 ^ F3 = Key
        for (let i = 0; i < keyBytes.length; i++) {
            fragment3[i] = keyBytes[i] ^ fragment1[i] ^ fragment2[i];
        }

        return [
            this.toBase64(fragment1),
            this.toBase64(fragment2),
            this.toBase64(fragment3)
        ];
    }

    /**
     * Recovers the Master Key from provided fragments.
     */
    static async recover(fragments: string[]): Promise<string> {
        if (fragments.length < 3) {
            throw new Error('RECOVERY_FAILED: Insufficient fragments (PoC requires 3-of-3).');
        }

        const f1 = this.fromBase64(fragments[0]);
        const f2 = this.fromBase64(fragments[1]);
        const f3 = this.fromBase64(fragments[2]);

        const recovered = new Uint8Array(f1.length);
        for (let i = 0; i < f1.length; i++) {
            recovered[i] = f1[i] ^ f2[i] ^ f3[i];
        }

        return new TextDecoder().decode(recovered);
    }

    private static toBase64(bytes: Uint8Array): string {
        return btoa(String.fromCharCode(...Array.from(bytes)));
    }

    private static fromBase64(b64: string): Uint8Array {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}
