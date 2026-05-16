import { describe, test, expect, beforeAll } from 'vitest';
import {
    createSign1,
    verifySign1,
    decodeCoseSign1,
    createMac0,
    verifyMac0,
    decodeCoseMac0,
    deriveSessionMacKey,
    COSE_HEADER,
    COSE_ALG,
    COSE_MAC_ALG,
} from '../src/cose';
import { encode } from '../src/cbor';

// ─── Test Key Setup ─────────────────────────────────────────────────────────

let keyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair;
let ecdhKeyPairA: CryptoKeyPair;
let ecdhKeyPairB: CryptoKeyPair;

beforeAll(async () => {
    // Generate ES256 (P-256) key pair for testing
    keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
    );
    // Second key pair for negative tests
    otherKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
    );
    // ECDH key pairs for Mac0 / key derivation tests
    ecdhKeyPairA = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits', 'deriveKey'],
    );
    ecdhKeyPairB = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits', 'deriveKey'],
    );
});

// ─── Roundtrip Tests ────────────────────────────────────────────────────────

describe('COSE_Sign1 create + verify', () => {
    test('roundtrip: sign then verify succeeds', async () => {
        const payload = encode({ docType: 'org.iso.18013.5.1.mDL', version: '1.0' });

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        expect(signed).toBeInstanceOf(Uint8Array);
        expect(signed.length).toBeGreaterThan(0);

        const result = await verifySign1(signed, keyPair.publicKey);

        expect(result.valid).toBe(true);
        expect(result.payload).toBeInstanceOf(Uint8Array);
        expect(result.protectedHeaders.get(COSE_HEADER.ALG)).toBe(COSE_ALG.ES256);
    });

    test('roundtrip: payload content survives sign+verify', async () => {
        const originalData = { claim: 'age_over_18', value: true };
        const payload = encode(originalData);

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const result = await verifySign1(signed, keyPair.publicKey);
        expect(result.valid).toBe(true);

        // Decode the recovered payload
        const { decode } = await import('../src/cbor');
        const recovered = decode<typeof originalData>(result.payload!);
        expect(recovered.claim).toBe('age_over_18');
        expect(recovered.value).toBe(true);
    });

    test('roundtrip: small payload (single byte)', async () => {
        const payload = new Uint8Array([0x42]);

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const result = await verifySign1(signed, keyPair.publicKey);
        expect(result.valid).toBe(true);
        expect(Array.from(result.payload!)).toEqual([0x42]);
    });

    test('roundtrip: large payload (1KB)', async () => {
        const payload = crypto.getRandomValues(new Uint8Array(1024));

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const result = await verifySign1(signed, keyPair.publicKey);
        expect(result.valid).toBe(true);
        expect(Array.from(result.payload!)).toEqual(Array.from(payload));
    });
});

// ─── Header Tests ───────────────────────────────────────────────────────────

describe('COSE_Sign1 headers', () => {
    test('protected headers contain alg=ES256', async () => {
        const payload = encode('test');

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const parsed = decodeCoseSign1(signed);
        expect(parsed.decodedProtectedHeaders.get(COSE_HEADER.ALG)).toBe(COSE_ALG.ES256);
    });

    test('extra protected headers are included', async () => {
        const payload = encode('test');
        const kid = new TextEncoder().encode('key-1');

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
            extraProtectedHeaders: new Map([[COSE_HEADER.KID, kid]]),
        });

        const parsed = decodeCoseSign1(signed);
        expect(parsed.decodedProtectedHeaders.get(COSE_HEADER.ALG)).toBe(COSE_ALG.ES256);
        const recoveredKid = parsed.decodedProtectedHeaders.get(COSE_HEADER.KID);
        expect(recoveredKid).toBeInstanceOf(Uint8Array);
        expect(Array.from(recoveredKid as Uint8Array)).toEqual(Array.from(kid));
    });

    test('unprotected headers are preserved', async () => {
        const payload = encode('test');
        const unprotected = new Map<number, unknown>([[COSE_HEADER.KID, 'my-key-id']]);

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
            unprotectedHeaders: unprotected,
        });

        const parsed = decodeCoseSign1(signed);
        // cborg may decode the Map as a plain object with string keys
        const kid = parsed.unprotectedHeaders.get(COSE_HEADER.KID)
            ?? parsed.unprotectedHeaders.get(4);
        expect(kid).toBe('my-key-id');
    });
});

// ─── Verification Negative Tests ────────────────────────────────────────────

describe('COSE_Sign1 verification failures', () => {
    test('verify fails with wrong public key', async () => {
        const payload = encode({ test: 'data' });

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const result = await verifySign1(signed, otherKeyPair.publicKey);
        expect(result.valid).toBe(false);
        expect(result.payload).toBeNull();
    });

    test('verify fails when payload is tampered', async () => {
        const payload = encode({ test: 'original' });

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        // Tamper with the COSE_Sign1 bytes: find the payload and modify it
        const parsed = decodeCoseSign1(signed);
        const tamperedPayload = encode({ test: 'tampered' });

        // Rebuild with tampered payload but original signature
        const tamperedArray = [
            parsed.protectedHeaders,
            parsed.unprotectedHeaders,
            tamperedPayload,
            parsed.signature,
        ];
        const tamperedBytes = prependTag18(encode(tamperedArray));

        const result = await verifySign1(tamperedBytes, keyPair.publicKey);
        expect(result.valid).toBe(false);
    });

    test('verify fails when signature is corrupted', async () => {
        const payload = encode('test');

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        // Corrupt the last few bytes (signature area)
        const corrupted = new Uint8Array(signed);
        corrupted[corrupted.length - 1] ^= 0xff;
        corrupted[corrupted.length - 2] ^= 0xff;

        const result = await verifySign1(corrupted, keyPair.publicKey);
        expect(result.valid).toBe(false);
    });

    test('verify fails with mismatched externalAad', async () => {
        const payload = encode('test');
        const aad = new TextEncoder().encode('context-binding');

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
            externalAad: aad,
        });

        // Verify with different AAD
        const wrongAad = new TextEncoder().encode('wrong-context');
        const result = await verifySign1(signed, keyPair.publicKey, wrongAad);
        expect(result.valid).toBe(false);
    });

    test('verify succeeds with matching externalAad', async () => {
        const payload = encode('test');
        const aad = new TextEncoder().encode('session-transcript');

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
            externalAad: aad,
        });

        const result = await verifySign1(signed, keyPair.publicKey, aad);
        expect(result.valid).toBe(true);
    });
});

// ─── Decode Tests ───────────────────────────────────────────────────────────

describe('COSE_Sign1 decode (structural)', () => {
    test('decodeCoseSign1 returns all components', async () => {
        const payload = encode({ data: 42 });

        const signed = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const parsed = decodeCoseSign1(signed);

        expect(parsed.protectedHeaders).toBeInstanceOf(Uint8Array);
        expect(parsed.protectedHeaders.length).toBeGreaterThan(0);
        expect(parsed.decodedProtectedHeaders).toBeInstanceOf(Map);
        expect(parsed.payload).toBeInstanceOf(Uint8Array);
        expect(parsed.signature).toBeInstanceOf(Uint8Array);
        // ES256 signature is 64 bytes (r || s, each 32 bytes)
        expect(parsed.signature.length).toBe(64);
    });

    test('decodeCoseSign1 rejects non-array input', () => {
        const invalid = encode('not-an-array');
        expect(() => decodeCoseSign1(invalid)).toThrow('expected 4-element array');
    });

    test('decodeCoseSign1 rejects wrong-length array', () => {
        const tooShort = encode([new Uint8Array(0), {}]);
        expect(() => decodeCoseSign1(tooShort)).toThrow('expected 4-element array');
    });
});

// ─── COSE Constants ─────────────────────────────────────────────────────────

describe('COSE constants', () => {
    test('COSE_ALG.ES256 is -7', () => {
        expect(COSE_ALG.ES256).toBe(-7);
    });

    test('COSE_HEADER.ALG is 1', () => {
        expect(COSE_HEADER.ALG).toBe(1);
    });

    test('COSE_HEADER.KID is 4', () => {
        expect(COSE_HEADER.KID).toBe(4);
    });
});

// ─── Determinism Tests ──────────────────────────────────────────────────────

describe('COSE_Sign1 determinism', () => {
    test('two signatures over same payload differ (ECDSA is non-deterministic)', async () => {
        const payload = encode('same-data');

        const signed1 = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });
        const signed2 = await createSign1({
            payload,
            privateKey: keyPair.privateKey,
        });

        const parsed1 = decodeCoseSign1(signed1);
        const parsed2 = decodeCoseSign1(signed2);

        // Signatures should differ (ECDSA uses random k)
        expect(Array.from(parsed1.signature)).not.toEqual(Array.from(parsed2.signature));

        // But both should verify
        const result1 = await verifySign1(signed1, keyPair.publicKey);
        const result2 = await verifySign1(signed2, keyPair.publicKey);
        expect(result1.valid).toBe(true);
        expect(result2.valid).toBe(true);
    });
});

// ─── COSE_Mac0 create + verify ──────────────────────────────────────────────

describe('COSE_Mac0 create + verify', () => {
    async function makeMacKey(): Promise<CryptoKey> {
        return deriveSessionMacKey(ecdhKeyPairA.privateKey, ecdhKeyPairB.publicKey);
    }

    test('roundtrip: MAC then verify succeeds', async () => {
        const macKey = await makeMacKey();
        const payload = encode({ deviceNameSpaces: {} });

        const mac0 = await createMac0({ payload, macKey });
        expect(mac0).toBeInstanceOf(Uint8Array);
        expect(mac0[0]).toBe(0xd1); // Tag 17

        const result = await verifyMac0(mac0, macKey);
        expect(result.valid).toBe(true);
        expect(result.payload).toBeInstanceOf(Uint8Array);
        expect(result.protectedHeaders.get(COSE_HEADER.ALG)).toBe(COSE_MAC_ALG.HMAC_256_256);
    });

    test('roundtrip: payload content survives MAC+verify', async () => {
        const macKey = await makeMacKey();
        const originalData = { claim: 'age_over_18', value: true };
        const payload = encode(originalData);

        const mac0 = await createMac0({ payload, macKey });
        const result = await verifyMac0(mac0, macKey);
        expect(result.valid).toBe(true);

        const { decode } = await import('../src/cbor');
        const recovered = decode<typeof originalData>(result.payload!);
        expect(recovered.claim).toBe('age_over_18');
        expect(recovered.value).toBe(true);
    });

    test('verify fails with wrong key', async () => {
        const macKey = await makeMacKey();
        const payload = encode({ test: 'data' });
        const mac0 = await createMac0({ payload, macKey });

        // Derive a different key
        const wrongKey = await deriveSessionMacKey(ecdhKeyPairB.privateKey, ecdhKeyPairB.publicKey);
        const result = await verifyMac0(mac0, wrongKey);
        expect(result.valid).toBe(false);
        expect(result.payload).toBeNull();
    });

    test('verify fails when payload is tampered', async () => {
        const macKey = await makeMacKey();
        const payload = encode({ test: 'original' });
        const mac0 = await createMac0({ payload, macKey });

        // Parse, tamper payload, rebuild
        const parsed = decodeCoseMac0(mac0);
        const tamperedPayload = encode({ test: 'tampered' });
        const tamperedArray = [
            parsed.protectedHeaders,
            parsed.unprotectedHeaders,
            tamperedPayload,
            parsed.tag,
        ];
        const tamperedBytes = prependTag17(encode(tamperedArray));

        const result = await verifyMac0(tamperedBytes, macKey);
        expect(result.valid).toBe(false);
    });

    test('verify succeeds with matching externalAad', async () => {
        const macKey = await makeMacKey();
        const payload = encode('test');
        const aad = new TextEncoder().encode('session-transcript');

        const mac0 = await createMac0({ payload, macKey, externalAad: aad });
        const result = await verifyMac0(mac0, macKey, aad);
        expect(result.valid).toBe(true);
    });

    test('verify fails with mismatched externalAad', async () => {
        const macKey = await makeMacKey();
        const payload = encode('test');
        const aad = new TextEncoder().encode('context-binding');

        const mac0 = await createMac0({ payload, macKey, externalAad: aad });
        const wrongAad = new TextEncoder().encode('wrong-context');
        const result = await verifyMac0(mac0, macKey, wrongAad);
        expect(result.valid).toBe(false);
    });

    test('verify fails when tag is corrupted', async () => {
        const macKey = await makeMacKey();
        const payload = encode('test');
        const mac0 = await createMac0({ payload, macKey });

        const corrupted = new Uint8Array(mac0);
        corrupted[corrupted.length - 1] ^= 0xff;
        corrupted[corrupted.length - 2] ^= 0xff;

        const result = await verifyMac0(corrupted, macKey);
        expect(result.valid).toBe(false);
    });
});

// ─── COSE_Mac0 decode (structural) ──────────────────────────────────────────

describe('COSE_Mac0 decode (structural)', () => {
    test('decodeCoseMac0 returns all components', async () => {
        const macKey = await deriveSessionMacKey(ecdhKeyPairA.privateKey, ecdhKeyPairB.publicKey);
        const payload = encode({ data: 42 });
        const mac0 = await createMac0({ payload, macKey });

        const parsed = decodeCoseMac0(mac0);
        expect(parsed.protectedHeaders).toBeInstanceOf(Uint8Array);
        expect(parsed.decodedProtectedHeaders).toBeInstanceOf(Map);
        expect(parsed.decodedProtectedHeaders.get(COSE_HEADER.ALG)).toBe(COSE_MAC_ALG.HMAC_256_256);
        expect(parsed.payload).toBeInstanceOf(Uint8Array);
        // HMAC-SHA-256 tag is 32 bytes
        expect(parsed.tag.length).toBe(32);
    });

    test('decodeCoseMac0 rejects non-array input', () => {
        expect(() => decodeCoseMac0(encode('not-an-array'))).toThrow('expected 4-element array');
    });

    test('decodeCoseMac0 rejects wrong-length array', () => {
        expect(() => decodeCoseMac0(encode([new Uint8Array(0), {}]))).toThrow('expected 4-element array');
    });
});

// ─── deriveSessionMacKey (ECDH + HKDF) ─────────────────────────────────────

describe('deriveSessionMacKey', () => {
    test('both sides derive the same key (symmetric)', async () => {
        // A→B and B→A should produce the same shared secret
        const keyAB = await deriveSessionMacKey(ecdhKeyPairA.privateKey, ecdhKeyPairB.publicKey);
        const keyBA = await deriveSessionMacKey(ecdhKeyPairB.privateKey, ecdhKeyPairA.publicKey);

        // Verify symmetry: MAC with one key, verify with the other
        const payload = encode({ test: 'symmetry' });
        const mac0 = await createMac0({ payload, macKey: keyAB });
        const result = await verifyMac0(mac0, keyBA);
        expect(result.valid).toBe(true);
    });

    test('different key pairs produce different MAC keys', async () => {
        const key1 = await deriveSessionMacKey(ecdhKeyPairA.privateKey, ecdhKeyPairB.publicKey);
        // Same party with itself — different shared secret
        const key2 = await deriveSessionMacKey(ecdhKeyPairA.privateKey, ecdhKeyPairA.publicKey);

        const payload = encode({ test: 'isolation' });
        const mac0 = await createMac0({ payload, macKey: key1 });
        const result = await verifyMac0(mac0, key2);
        expect(result.valid).toBe(false);
    });

    test('custom salt and info produce different keys', async () => {
        const key1 = await deriveSessionMacKey(
            ecdhKeyPairA.privateKey,
            ecdhKeyPairB.publicKey,
            new Uint8Array(32),
            new TextEncoder().encode('EMacKey'),
        );
        const key2 = await deriveSessionMacKey(
            ecdhKeyPairA.privateKey,
            ecdhKeyPairB.publicKey,
            new Uint8Array(32),
            new TextEncoder().encode('DifferentInfo'),
        );

        const payload = encode({ test: 'info-isolation' });
        const mac0 = await createMac0({ payload, macKey: key1 });
        const result = await verifyMac0(mac0, key2);
        expect(result.valid).toBe(false);
    });
});

// ─── COSE_MAC_ALG constants ─────────────────────────────────────────────────

describe('COSE_MAC_ALG constants', () => {
    test('HMAC_256_256 is 5', () => {
        expect(COSE_MAC_ALG.HMAC_256_256).toBe(5);
    });
});

// ─── Helper ─────────────────────────────────────────────────────────────────

/** Prepend CBOR Tag 18 to raw array bytes */
function prependTag18(arrayBytes: Uint8Array): Uint8Array {
    const result = new Uint8Array(1 + arrayBytes.length);
    result[0] = 0xd2; // Tag 18
    result.set(arrayBytes, 1);
    return result;
}

/** Prepend CBOR Tag 17 to raw array bytes */
function prependTag17(arrayBytes: Uint8Array): Uint8Array {
    const result = new Uint8Array(1 + arrayBytes.length);
    result[0] = 0xd1; // Tag 17
    result.set(arrayBytes, 1);
    return result;
}
