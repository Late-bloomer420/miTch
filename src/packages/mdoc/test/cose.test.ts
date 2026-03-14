import { describe, test, expect, beforeAll } from 'vitest';
import {
    createSign1,
    verifySign1,
    decodeCoseSign1,
    COSE_HEADER,
    COSE_ALG,
} from '../src/cose';
import { encode } from '../src/cbor';

// ─── Test Key Setup ─────────────────────────────────────────────────────────

let keyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair;

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

// ─── Helper ─────────────────────────────────────────────────────────────────

/** Prepend CBOR Tag 18 to raw array bytes */
function prependTag18(arrayBytes: Uint8Array): Uint8Array {
    const result = new Uint8Array(1 + arrayBytes.length);
    result[0] = 0xd2; // Tag 18
    result.set(arrayBytes, 1);
    return result;
}
