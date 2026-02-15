import { describe, it, expect } from 'vitest';
import { EphemeralKey } from '../src/ephemeral_key';
import { webcrypto } from 'node:crypto';

describe('EphemeralKey (Production Ready)', () => {

    it('should generate a key and verify shred proof', async () => {
        const key = EphemeralKey.generate(32);

        // Use it
        const result = await key.use(async (k) => {
            expect(k.length).toBe(32);
            return "success";
        });

        expect(result).toBe("success");
        expect(key.isShredded()).toBe(true);

        // Verify Proof
        const proof = key.getShredProof();
        expect(proof.operationSuccess).toBe(true);
        expect(proof.shredMethod).toContain("fill(0)");

        // Post shred hash of 32 zeros
        const zeros = new Uint8Array(32);
        const expectedHash = webcrypto.createHash('sha256').update(zeros).digest('hex');
        expect(proof.postShredHash).toBe(expectedHash);
    });

    it('should clear call site buffer on import', () => {
        const sensitive = new Uint8Array([1, 2, 3, 4]);
        const originalCopy = new Uint8Array(sensitive); // Keep a backup to verify we had data

        const key = EphemeralKey.import(sensitive);

        // Caller's buffer should be zeroed now
        expect(sensitive[0]).toBe(0);
        expect(sensitive[1]).toBe(0);
        expect(sensitive[2]).toBe(0);
        expect(sensitive[3]).toBe(0);

        // But we must attest we can still use the internal key
        // key.use(...) would work
    });

    it('should handle exceptions gracefully', async () => {
        const key = EphemeralKey.generate(16);

        try {
            await key.use(async () => {
                throw new Error("Oops");
            });
        } catch (e) {
            // Expected
        }

        expect(key.isShredded()).toBe(true);
        const proof = key.getShredProof();
        expect(proof.operationSuccess).toBe(false);
    });

    it('should prevent reuse', async () => {
        const key = EphemeralKey.generate(16);
        await key.use(async () => "done");

        await expect(key.use(async () => "again")).rejects.toThrow("destroyed");
    });
});
