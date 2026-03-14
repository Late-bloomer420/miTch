/**
 * @module @mitch/mdoc/cbor
 *
 * Minimal CBOR codec wrapper for mdoc document encoding.
 * Uses cborg for RFC 8949 compliant encode/decode.
 *
 * Scope: encode/decode of mdoc-relevant CBOR structures.
 * COSE signing/verification is NOT included (future follow-up).
 */

import { encode as cborgEncode, decode as cborgDecode } from 'cborg';

/**
 * CBOR Tag numbers relevant to ISO 18013-5 mdoc.
 */
export const CBOR_TAGS = {
    /** Tag 24: Embedded CBOR data item (used for IssuerSignedItem encoding) */
    EMBEDDED_CBOR: 24,
    /** Tag 18: COSE_Sign1 (single-signer signed data) */
    COSE_SIGN1: 18,
    /** Tag 17: COSE_Mac0 (MAC without recipients) */
    COSE_MAC0: 17,
} as const;

/**
 * cborg decode options with tag handlers for mdoc-relevant CBOR tags.
 * Tags are a sparse array indexed by tag number (cborg TagDecoder[] API).
 * - Tag 17 = COSE_Mac0: pass through as-is.
 * - Tag 18 = COSE_Sign1: pass through as-is.
 * - Tag 24 = embedded CBOR: decode the inner byte string as CBOR.
 */
const decodeTags = [] as ((inner: any) => any)[];
decodeTags[CBOR_TAGS.COSE_MAC0] = (value: any) => value;
decodeTags[CBOR_TAGS.COSE_SIGN1] = (value: any) => value;
decodeTags[CBOR_TAGS.EMBEDDED_CBOR] = (innerBytes: any) => cborgDecode(innerBytes);
const DECODE_OPTIONS = { tags: decodeTags };

/**
 * Encode a JavaScript value to CBOR bytes.
 *
 * Supports all CBOR major types: integers, byte strings, text strings,
 * arrays, maps, booleans, null, and tagged values.
 */
export function encode(value: unknown): Uint8Array {
    return cborgEncode(value);
}

/**
 * Decode CBOR bytes to a JavaScript value.
 * Handles Tag 24 (embedded CBOR) automatically.
 *
 * @throws {Error} If the input is not valid CBOR.
 */
export function decode<T = unknown>(data: Uint8Array): T {
    return cborgDecode(data, DECODE_OPTIONS) as T;
}

/**
 * CBOR encoding of Tag 24 header.
 * Tag 24 in CBOR: major type 6 with value 24 = 0xd8 0x18.
 */
const TAG_24_HEADER = new Uint8Array([0xd8, 0x18]);

/**
 * Encode a CBOR byte string length prefix.
 */
function encodeBstrLength(length: number): Uint8Array {
    if (length < 24) {
        return new Uint8Array([0x40 | length]);
    } else if (length < 256) {
        return new Uint8Array([0x58, length]);
    } else if (length < 65536) {
        return new Uint8Array([0x59, (length >> 8) & 0xff, length & 0xff]);
    }
    // For very large payloads (> 64KB) — unlikely for mdoc items
    const buf = new Uint8Array(5);
    buf[0] = 0x5a;
    buf[1] = (length >> 24) & 0xff;
    buf[2] = (length >> 16) & 0xff;
    buf[3] = (length >> 8) & 0xff;
    buf[4] = length & 0xff;
    return buf;
}

/**
 * Encode a value as Tag 24 (embedded CBOR).
 * ISO 18013-5 uses this to wrap IssuerSignedItem bytes in the MSO digest calculation.
 *
 * Produces: CBOR Tag 24 header + byte string containing CBOR-encoded inner value.
 */
export function encodeEmbeddedCbor(value: unknown): Uint8Array {
    const innerBytes = encode(value);
    const lengthPrefix = encodeBstrLength(innerBytes.length);
    const result = new Uint8Array(TAG_24_HEADER.length + lengthPrefix.length + innerBytes.length);
    result.set(TAG_24_HEADER, 0);
    result.set(lengthPrefix, TAG_24_HEADER.length);
    result.set(innerBytes, TAG_24_HEADER.length + lengthPrefix.length);
    return result;
}

/**
 * Decode a Tag 24 (embedded CBOR) value.
 * Returns the decoded inner value.
 *
 * Uses cborg with Tag 24 handler to auto-decode the embedded CBOR.
 */
export function decodeEmbeddedCbor<T = unknown>(data: Uint8Array): T {
    return decode<T>(data);
}
