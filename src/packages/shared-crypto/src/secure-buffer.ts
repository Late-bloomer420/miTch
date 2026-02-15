/**
 * SecureBuffer: A memory-safe container for sensitive byte arrays.
 * 
 * Unlike standard Uint8Array, SecureBuffer provides an explicit `.shred()` 
 * method that overwrites the memory with zeroes before releasing it, 
 * mitigating risks from heap-scanning attacks.
 */
export class SecureBuffer {
    private data: Uint8Array | null;
    private shredded: boolean = false;

    constructor(sizeOrData: number | Uint8Array) {
        if (typeof sizeOrData === 'number') {
            this.data = new Uint8Array(sizeOrData);
        } else {
            // Copy data to ensure we own the buffer
            this.data = new Uint8Array(sizeOrData);
        }
    }

    /**
     * Access the underlying view.
     * @throws if shredded
     */
    get view(): Uint8Array {
        if (this.shredded || !this.data) {
            throw new Error('SECURITY VIOLATION: Access to shredded SecureBuffer');
        }
        return this.data;
    }

    /**
     * Explicit Memory Shredding: Overwrites every byte with 0x00.
     * This is a "Forensic-Level" wipe that doesn't wait for the GC.
     */
    shred(): void {
        if (this.shredded || !this.data) return;

        // T-21: Forensic Overwrite
        for (let i = 0; i < this.data.length; i++) {
            this.data[i] = 0;
        }

        this.data = null;
        this.shredded = true;
    }

    /**
     * Create a SecureBuffer from a string (UTF-8).
     */
    static fromString(text: string): SecureBuffer {
        const encoder = new TextEncoder();
        return new SecureBuffer(encoder.encode(text));
    }
}
