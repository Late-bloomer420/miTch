export interface ProofOfExistence {
    type: 'ProofOfExistence';
    hash: string;
    hashAlg: 'SHA-256';
    mediaType: string;
    description: string;
    createdAt: string;
    byteLength: number;
    signerDid?: string;
}

export class DocumentService {
    /**
     * Calculates the SHA-256 hash of a file client-side.
     * The file never leaves the user's device.
     */
    static async hashFile(file: File): Promise<string> {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    /**
     * Creates the structural payload for the proof.
     */
    static createProofOfExistence(hash: string, file: File, description: string): ProofOfExistence {
        return {
            type: 'ProofOfExistence',
            hash: hash,
            hashAlg: 'SHA-256',
            mediaType: file.type || 'application/octet-stream',
            description: description,
            createdAt: new Date().toISOString(),
            byteLength: file.size
        };
    }
}
