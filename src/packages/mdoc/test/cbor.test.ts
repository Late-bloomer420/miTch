import { describe, test, expect } from 'vitest';
import { encode, decode, encodeEmbeddedCbor, decodeEmbeddedCbor, CBOR_TAGS } from '../src/cbor';
import type { IssuerSignedItem } from '../src/mdoc-types';
import { MDL_NAMESPACE, MDL_ELEMENTS } from '../src/mdoc-types';

describe('CBOR codec', () => {
    // ─── Primitive roundtrips ──────────────────────────────────────────

    test('roundtrip: positive integer', () => {
        const value = 42;
        const encoded = encode(value);
        expect(encoded).toBeInstanceOf(Uint8Array);
        expect(encoded.length).toBeGreaterThan(0);
        expect(decode(encoded)).toBe(value);
    });

    test('roundtrip: negative integer', () => {
        const value = -100;
        const encoded = encode(value);
        expect(decode(encoded)).toBe(value);
    });

    test('roundtrip: zero', () => {
        expect(decode(encode(0))).toBe(0);
    });

    test('roundtrip: text string', () => {
        const value = 'org.iso.18013.5.1.mDL';
        const encoded = encode(value);
        expect(decode(encoded)).toBe(value);
    });

    test('roundtrip: empty string', () => {
        expect(decode(encode(''))).toBe('');
    });

    test('roundtrip: boolean true/false', () => {
        expect(decode(encode(true))).toBe(true);
        expect(decode(encode(false))).toBe(false);
    });

    test('roundtrip: null', () => {
        expect(decode(encode(null))).toBeNull();
    });

    test('roundtrip: byte string (Uint8Array)', () => {
        const value = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const encoded = encode(value);
        const decoded = decode<Uint8Array>(encoded);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(Array.from(decoded)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    // ─── Compound types ───────────────────────────────────────────────

    test('roundtrip: array', () => {
        const value = [1, 'two', true, null];
        const encoded = encode(value);
        expect(decode(encoded)).toEqual(value);
    });

    test('roundtrip: nested array', () => {
        const value = [[1, 2], [3, [4, 5]]];
        const encoded = encode(value);
        expect(decode(encoded)).toEqual(value);
    });

    test('roundtrip: object (CBOR map with string keys)', () => {
        const value = { docType: 'org.iso.18013.5.1.mDL', version: '1.0' };
        const encoded = encode(value);
        const decoded = decode<Record<string, string>>(encoded);
        expect(decoded.docType).toBe('org.iso.18013.5.1.mDL');
        expect(decoded.version).toBe('1.0');
    });

    test('roundtrip: nested object', () => {
        const value = {
            outer: { inner: 'value', count: 7 },
            list: [1, 2, 3],
        };
        const encoded = encode(value);
        const decoded = decode<typeof value>(encoded);
        expect(decoded.outer.inner).toBe('value');
        expect(decoded.outer.count).toBe(7);
        expect(decoded.list).toEqual([1, 2, 3]);
    });

    // ─── mdoc-relevant structures ─────────────────────────────────────

    test('roundtrip: IssuerSignedItem-like structure', () => {
        const random = crypto.getRandomValues(new Uint8Array(16));
        const item: IssuerSignedItem = {
            digestID: 0,
            random,
            elementIdentifier: MDL_ELEMENTS.FAMILY_NAME,
            elementValue: 'Müller',
        };

        const encoded = encode(item);
        const decoded = decode<IssuerSignedItem>(encoded);

        expect(decoded.digestID).toBe(0);
        expect(decoded.elementIdentifier).toBe('family_name');
        expect(decoded.elementValue).toBe('Müller');
        expect(Array.from(decoded.random as Uint8Array)).toEqual(Array.from(random));
    });

    test('roundtrip: multiple IssuerSignedItems in namespace map', () => {
        const items = [
            {
                digestID: 0,
                random: crypto.getRandomValues(new Uint8Array(16)),
                elementIdentifier: MDL_ELEMENTS.FAMILY_NAME,
                elementValue: 'Schmidt',
            },
            {
                digestID: 1,
                random: crypto.getRandomValues(new Uint8Array(16)),
                elementIdentifier: MDL_ELEMENTS.AGE_OVER_18,
                elementValue: true,
            },
            {
                digestID: 2,
                random: crypto.getRandomValues(new Uint8Array(16)),
                elementIdentifier: MDL_ELEMENTS.BIRTH_DATE,
                elementValue: '1990-05-15',
            },
        ];

        const namespaceMap = { [MDL_NAMESPACE]: items };
        const encoded = encode(namespaceMap);
        const decoded = decode<Record<string, IssuerSignedItem[]>>(encoded);

        expect(decoded[MDL_NAMESPACE]).toHaveLength(3);
        expect(decoded[MDL_NAMESPACE][0].elementIdentifier).toBe('family_name');
        expect(decoded[MDL_NAMESPACE][1].elementValue).toBe(true);
        expect(decoded[MDL_NAMESPACE][2].elementValue).toBe('1990-05-15');
    });

    test('roundtrip: large integer (digestID)', () => {
        const value = { digestID: 65535, data: 'test' };
        const encoded = encode(value);
        const decoded = decode<typeof value>(encoded);
        expect(decoded.digestID).toBe(65535);
    });

    // ─── Embedded CBOR (Tag 24) ───────────────────────────────────────

    test('encodeEmbeddedCbor wraps value in Tag 24', () => {
        const item = { elementIdentifier: 'family_name', elementValue: 'Test' };
        const embedded = encodeEmbeddedCbor(item);
        expect(embedded).toBeInstanceOf(Uint8Array);
        expect(embedded.length).toBeGreaterThan(0);
        // Should be decodable
        const recovered = decodeEmbeddedCbor<typeof item>(embedded);
        expect(recovered.elementIdentifier).toBe('family_name');
        expect(recovered.elementValue).toBe('Test');
    });

    // ─── Edge cases ───────────────────────────────────────────────────

    test('decode rejects invalid CBOR', () => {
        const garbage = new Uint8Array([0xff, 0xfe, 0xfd]);
        expect(() => decode(garbage)).toThrow();
    });

    test('roundtrip: empty object', () => {
        expect(decode(encode({}))).toEqual({});
    });

    test('roundtrip: empty array', () => {
        expect(decode(encode([]))).toEqual([]);
    });

    test('roundtrip: Unicode text (German umlauts)', () => {
        const value = 'Österreich Ärztekammer Überweisung';
        expect(decode(encode(value))).toBe(value);
    });

    test('CBOR_TAGS constants are correct', () => {
        expect(CBOR_TAGS.EMBEDDED_CBOR).toBe(24);
        expect(CBOR_TAGS.COSE_SIGN1).toBe(18);
        expect(CBOR_TAGS.COSE_MAC0).toBe(17);
    });
});
