/**
 * RecoveryService — Shamir's Secret Sharing (2-of-3)
 * F-01 fix verification: confirms real GF(2^8) SSS, not XOR 3-of-3.
 */
import { describe, it, expect } from 'vitest';
import { RecoveryService } from '../src/recovery.js';

const KEY_HEX = 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f10';

describe('RecoveryService — Shamir 2-of-3 SSS', () => {
    it('round-trip: any 2 of 3 shares recover the original key', async () => {
        const [s1, s2, s3] = await RecoveryService.splitMasterKey(KEY_HEX);
        // All three 2-of-3 combinations must work
        expect(await RecoveryService.recover([s1, s2])).toBe(KEY_HEX);
        expect(await RecoveryService.recover([s1, s3])).toBe(KEY_HEX);
        expect(await RecoveryService.recover([s2, s3])).toBe(KEY_HEX);
    });

    it('round-trip also works with all 3 shares', async () => {
        const [s1, s2, s3] = await RecoveryService.splitMasterKey(KEY_HEX);
        expect(await RecoveryService.recover([s1, s2, s3])).toBe(KEY_HEX);
    });

    it('each split produces different shares (randomised coefficients)', async () => {
        const [a1] = await RecoveryService.splitMasterKey(KEY_HEX);
        const [b1] = await RecoveryService.splitMasterKey(KEY_HEX);
        expect(a1).not.toBe(b1);
    });

    it('throws with fewer than 2 shares', async () => {
        const [s1] = await RecoveryService.splitMasterKey(KEY_HEX);
        await expect(RecoveryService.recover([s1])).rejects.toThrow('RECOVERY_FAILED');
    });

    it('wrong share combination returns garbage (not the original key)', async () => {
        const [s1, , s3] = await RecoveryService.splitMasterKey(KEY_HEX);
        const [r1]       = await RecoveryService.splitMasterKey('aabbccddeeff00112233445566778899');
        // Mix shares from two different splits — result should not match KEY_HEX
        const wrong = await RecoveryService.recover([s1, r1]).catch(() => '__ERROR__');
        expect(wrong).not.toBe(KEY_HEX);
        // s3 is a valid share but from the right split — using it correctly still works
        expect(await RecoveryService.recover([s1, s3])).toBe(KEY_HEX);
    });

    it('works with an empty string key', async () => {
        const shares = await RecoveryService.splitMasterKey('');
        expect(await RecoveryService.recover(shares.slice(0, 2))).toBe('');
    });
});
