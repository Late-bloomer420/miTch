 
import { describe, it, expect, beforeAll } from 'vitest';
import {
    generateECDHKeyPair,
    deriveSharedHMACKey,
    computeMAC,
    verifyMAC,
    macSDJWTDisclosures,
    verifySDJWTDisclosureMAC,
    type ECDHKeyPair,
} from '../src/mac-verify';

// ─── C-02: ECDH Key Agreement ─────────────────────────────────────────────────

describe('ECDH Key Agreement', () => {
    let kp1: ECDHKeyPair;
    let kp2: ECDHKeyPair;

    beforeAll(async () => {
        kp1 = await generateECDHKeyPair();
        kp2 = await generateECDHKeyPair();
    });

    it('generates an ECDH P-256 key pair', () => {
        expect(kp1.privateKey).toBeDefined();
        expect(kp1.publicKey).toBeDefined();
        expect(kp1.privateKey.type).toBe('private');
        expect(kp1.publicKey.type).toBe('public');
        expect(kp1.privateKey.algorithm.name).toBe('ECDH');
    });

    it('derives the same HMAC key from both sides (Diffie-Hellman property)', async () => {
        // kp1.priv × kp2.pub == kp2.priv × kp1.pub
        const sharedKey1 = await deriveSharedHMACKey(kp1.privateKey, kp2.publicKey);
        const sharedKey2 = await deriveSharedHMACKey(kp2.privateKey, kp1.publicKey);

        // Both keys should produce the same MAC for the same input
        const mac1 = await computeMAC('test-message', sharedKey1);
        const mac2 = await computeMAC('test-message', sharedKey2);
        expect(mac1.mac).toBe(mac2.mac);
    });
});

// ─── C-02: MAC Computation ────────────────────────────────────────────────────

describe('HMAC-SHA-256 MAC', () => {
    let hmacKey: CryptoKey;

    beforeAll(async () => {
        const kp1 = await generateECDHKeyPair();
        const kp2 = await generateECDHKeyPair();
        hmacKey = await deriveSharedHMACKey(kp1.privateKey, kp2.publicKey);
    });

    it('computes a MAC and verifies it', async () => {
        const result = await computeMAC('hello BSI compliance', hmacKey);
        expect(result.mac).toBeTruthy();
        expect(result.alg).toBe('HMAC-SHA-256');
        expect(result.mac.length).toBe(64); // 256-bit hex

        const verification = await verifyMAC('hello BSI compliance', result.mac, hmacKey);
        expect(verification.ok).toBe(true);
    });

    it('rejects MAC over different message', async () => {
        const result = await computeMAC('original', hmacKey);
        const verification = await verifyMAC('tampered', result.mac, hmacKey);
        expect(verification.ok).toBe(false);
        expect(verification.error).toMatch(/mismatch/);
    });

    it('works with Uint8Array input', async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const result = await computeMAC(data, hmacKey);
        const verification = await verifyMAC(data, result.mac, hmacKey);
        expect(verification.ok).toBe(true);
    });

    it('produces different MACs for different messages', async () => {
        const mac1 = await computeMAC('message-a', hmacKey);
        const mac2 = await computeMAC('message-b', hmacKey);
        expect(mac1.mac).not.toBe(mac2.mac);
    });

    it('produces same MAC for same message (deterministic)', async () => {
        const mac1 = await computeMAC('deterministic', hmacKey);
        const mac2 = await computeMAC('deterministic', hmacKey);
        expect(mac1.mac).toBe(mac2.mac);
    });
});

// ─── C-02: SD-JWT Disclosure MAC ─────────────────────────────────────────────

describe('SD-JWT Disclosure MAC', () => {
    let hmacKey: CryptoKey;

    beforeAll(async () => {
        const kp1 = await generateECDHKeyPair();
        const kp2 = await generateECDHKeyPair();
        hmacKey = await deriveSharedHMACKey(kp1.privateKey, kp2.publicKey);
    });

    const disclosures = [
        'WyJzYWx0MSIsImZpcnN0X25hbWUiLCJNYXgiXQ',
        'WyJzYWx0MiIsImxhc3RfbmFtZSIsIk11c3Rlcm1hbm4iXQ',
        'WyJzYWx0MyIsImJpcnRoZGF0ZSIsIjE5OTAtMDEtMTUiXQ',
    ];

    it('computes and verifies MAC over disclosures', async () => {
        const result = await macSDJWTDisclosures(disclosures, hmacKey);
        const verification = await verifySDJWTDisclosureMAC(disclosures, result.mac, hmacKey);
        expect(verification.ok).toBe(true);
    });

    it('MAC is order-independent (sorted before hashing)', async () => {
        const mac1 = await macSDJWTDisclosures(disclosures, hmacKey);
        const mac2 = await macSDJWTDisclosures([...disclosures].reverse(), hmacKey);
        expect(mac1.mac).toBe(mac2.mac);
    });

    it('rejects MAC with wrong disclosure set', async () => {
        const result = await macSDJWTDisclosures(disclosures, hmacKey);
        const verification = await verifySDJWTDisclosureMAC(
            [...disclosures, 'extra-disclosure'], result.mac, hmacKey
        );
        expect(verification.ok).toBe(false);
    });
});
