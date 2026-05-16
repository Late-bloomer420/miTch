/**
 * @module @mitch/mdoc/cose
 *
 * Minimal COSE_Sign1 implementation for mdoc issuer/device authentication.
 * Implements RFC 9052 §4.3–4.4 (COSE Single Signer Data Object).
 *
 * Scope: ES256 (ECDSA P-256 + SHA-256) only.
 * Uses WebCrypto for signing/verification (browser + Node compatible).
 *
 * NOT included: Mac0, Sign (multi-signer), Encrypt, key management.
 */

import { encode, CBOR_TAGS } from './cbor.js';
import { decode as cborgDecode } from 'cborg';

/**
 * COSE-specific CBOR decode with integer map key support.
 * COSE headers use integer keys (1=alg, 4=kid), which cborg rejects
 * unless `useMaps: true` is set. This does NOT affect the general
 * cbor.decode() used elsewhere.
 */
const coseTags = [] as ((inner: any) => any)[];
coseTags[CBOR_TAGS.COSE_MAC0] = (value: any) => value;
coseTags[CBOR_TAGS.COSE_SIGN1] = (value: any) => value;
coseTags[CBOR_TAGS.EMBEDDED_CBOR] = (innerBytes: any) => cborgDecode(innerBytes, COSE_DECODE_OPTIONS);
const COSE_DECODE_OPTIONS = {
    useMaps: true,
    tags: coseTags,
};

function coseDecode<T = unknown>(data: Uint8Array): T {
    return cborgDecode(data, COSE_DECODE_OPTIONS) as T;
}

// ─── COSE Constants (RFC 9052 / IANA COSE registry) ─────────────────────────

/** COSE Header parameter keys (integer labels per RFC 9052 §3.1) */
export const COSE_HEADER = {
    /** Algorithm identifier */
    ALG: 1,
    /** Key identifier */
    KID: 4,
} as const;

/** COSE Algorithm identifiers (IANA COSE Algorithms registry) */
export const COSE_ALG = {
    /** ECDSA w/ SHA-256 (P-256) */
    ES256: -7,
} as const;

/** Tag 18 header bytes: major type 6 (tag) with value 18 = 0xd2 */
const TAG_18_HEADER = new Uint8Array([0xd2]);

/**
 * Convert a Uint8Array to a plain ArrayBuffer for WebCrypto compatibility.
 * TS 5.9 makes Uint8Array generic over ArrayBufferLike, but crypto.subtle
 * expects BufferSource with a concrete ArrayBuffer. This copy guarantees that.
 */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    return copy.buffer;
}

// ─── Types ──────────────────────────────────────────────────────────────────

/** COSE header map with integer keys */
export type CoseHeaderMap = Map<number, unknown>;

/** Decoded COSE_Sign1 structure */
export interface CoseSign1Structure {
    /** CBOR-encoded protected headers (raw bytes) */
    protectedHeaders: Uint8Array;
    /** Decoded protected header map */
    decodedProtectedHeaders: CoseHeaderMap;
    /** Unprotected headers */
    unprotectedHeaders: CoseHeaderMap;
    /** Payload (may be null for detached content) */
    payload: Uint8Array | null;
    /** Signature bytes */
    signature: Uint8Array;
}

/** Options for creating a COSE_Sign1 */
export interface Sign1CreateOptions {
    /** Payload to sign (CBOR-encoded content, e.g. MSO) */
    payload: Uint8Array;
    /** ECDSA P-256 private key (WebCrypto) */
    privateKey: CryptoKey;
    /** Additional protected headers (alg is set automatically) */
    extraProtectedHeaders?: Map<number, unknown>;
    /** Unprotected headers */
    unprotectedHeaders?: Map<number, unknown>;
    /** External additional authenticated data (default: empty) */
    externalAad?: Uint8Array;
}

/** Result of COSE_Sign1 verification */
export interface Sign1VerifyResult {
    /** Whether the signature is valid */
    valid: boolean;
    /** Decoded payload (if signature valid) */
    payload: Uint8Array | null;
    /** Decoded protected headers */
    protectedHeaders: CoseHeaderMap;
}

// ─── Sig_structure1 (RFC 9052 §4.4) ────────────────────────────────────────

/**
 * Build the Sig_structure1 for COSE_Sign1 signing/verification.
 *
 * Sig_structure1 = [
 *   context : "Signature1",
 *   body_protected : bstr,
 *   external_aad : bstr,
 *   payload : bstr
 * ]
 */
function buildSigStructure1(
    protectedHeaderBytes: Uint8Array,
    payload: Uint8Array,
    externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
    const structure = [
        'Signature1',
        protectedHeaderBytes,
        externalAad,
        payload,
    ];
    return encode(structure);
}

// ─── COSE_Sign1 Create ─────────────────────────────────────────────────────

/**
 * Create a COSE_Sign1 signed structure.
 *
 * Returns CBOR-encoded COSE_Sign1 tagged with Tag 18.
 * Algorithm: ES256 (ECDSA P-256 + SHA-256).
 *
 * @param opts - Signing options (payload, privateKey, optional headers)
 * @returns CBOR bytes: Tag 18 [ protected, unprotected, payload, signature ]
 */
export async function createSign1(opts: Sign1CreateOptions): Promise<Uint8Array> {
    const { payload, privateKey, externalAad } = opts;

    // Build protected headers: alg = ES256 (-7) + any extras
    const protectedMap = new Map<number, unknown>();
    protectedMap.set(COSE_HEADER.ALG, COSE_ALG.ES256);
    if (opts.extraProtectedHeaders) {
        for (const [k, v] of opts.extraProtectedHeaders) {
            protectedMap.set(k, v);
        }
    }

    // Encode protected headers as a CBOR map, then wrap as bstr
    const protectedHeaderBytes = encodeProtectedHeaders(protectedMap);

    // Build Sig_structure1
    const sigStructure = buildSigStructure1(protectedHeaderBytes, payload, externalAad);

    // Sign with ECDSA P-256 + SHA-256
    const signatureBuffer = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        toArrayBuffer(sigStructure),
    );
    const signature = new Uint8Array(signatureBuffer);

    // Unprotected headers
    const unprotected = opts.unprotectedHeaders ?? new Map<number, unknown>();

    // COSE_Sign1 = [ protected, unprotected, payload, signature ]
    const coseArray = [
        protectedHeaderBytes,
        unprotected,
        payload,
        signature,
    ];

    // Encode as CBOR array, then prepend Tag 18 header
    const arrayBytes = encode(coseArray);
    const result = new Uint8Array(TAG_18_HEADER.length + arrayBytes.length);
    result.set(TAG_18_HEADER, 0);
    result.set(arrayBytes, TAG_18_HEADER.length);
    return result;
}

// ─── COSE_Sign1 Verify ─────────────────────────────────────────────────────

/**
 * Verify a COSE_Sign1 structure.
 *
 * Accepts CBOR-encoded COSE_Sign1 (with or without Tag 18).
 * Currently supports ES256 only.
 *
 * @param coseSign1Bytes - CBOR-encoded COSE_Sign1
 * @param publicKey - ECDSA P-256 public key (WebCrypto)
 * @param externalAad - External additional authenticated data (default: empty)
 * @returns Verification result with payload and headers
 */
export async function verifySign1(
    coseSign1Bytes: Uint8Array,
    publicKey: CryptoKey,
    externalAad: Uint8Array = new Uint8Array(0),
): Promise<Sign1VerifyResult> {
    // Parse the COSE_Sign1 structure
    const parsed = decodeCoseSign1(coseSign1Bytes);

    // Verify algorithm is ES256
    const alg = parsed.decodedProtectedHeaders.get(COSE_HEADER.ALG);
    if (alg !== COSE_ALG.ES256) {
        return { valid: false, payload: null, protectedHeaders: parsed.decodedProtectedHeaders };
    }

    // Rebuild Sig_structure1 for verification
    const sigStructure = buildSigStructure1(
        parsed.protectedHeaders,
        parsed.payload ?? new Uint8Array(0),
        externalAad,
    );

    // Verify ECDSA signature
    const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        toArrayBuffer(parsed.signature),
        toArrayBuffer(sigStructure),
    );

    return {
        valid,
        payload: valid ? parsed.payload : null,
        protectedHeaders: parsed.decodedProtectedHeaders,
    };
}

// ─── COSE_Sign1 Decode (structural only, no signature check) ───────────────

/**
 * Decode a COSE_Sign1 structure without verifying the signature.
 * Useful for inspecting headers/payload before verification.
 *
 * @param coseSign1Bytes - CBOR-encoded COSE_Sign1 (with or without Tag 18)
 * @throws {Error} If the structure is not a valid COSE_Sign1 array
 */
export function decodeCoseSign1(coseSign1Bytes: Uint8Array): CoseSign1Structure {
    // Decode — our cbor.decode handles Tag 18 by passing through
    // (no tag handler registered for 18), so we decode the raw array
    const decoded = coseDecode<unknown[]>(coseSign1Bytes);

    // COSE_Sign1 is a 4-element array: [protected, unprotected, payload, signature]
    if (!Array.isArray(decoded) || decoded.length !== 4) {
        throw new Error('Invalid COSE_Sign1: expected 4-element array');
    }

    const [protectedHeaderBytes, unprotectedRaw, payloadRaw, signatureRaw] = decoded;

    if (!(protectedHeaderBytes instanceof Uint8Array)) {
        throw new Error('Invalid COSE_Sign1: protected headers must be a byte string');
    }
    if (!(signatureRaw instanceof Uint8Array)) {
        throw new Error('Invalid COSE_Sign1: signature must be a byte string');
    }

    // Decode protected headers (CBOR map inside the byte string)
    // With useMaps: true, cborg returns Maps with integer keys directly
    const protectedMap: CoseHeaderMap = protectedHeaderBytes.length > 0
        ? coseDecode<CoseHeaderMap>(protectedHeaderBytes)
        : new Map<number, unknown>();

    // Unprotected headers (already a Map from useMaps: true)
    const unprotectedHeaders: CoseHeaderMap = unprotectedRaw instanceof Map
        ? unprotectedRaw
        : new Map<number, unknown>();

    // Payload: bstr or null
    const payload = payloadRaw instanceof Uint8Array ? payloadRaw
        : payloadRaw === null ? null
        : null;

    return {
        protectedHeaders: protectedHeaderBytes,
        decodedProtectedHeaders: protectedMap,
        unprotectedHeaders,
        payload,
        signature: signatureRaw,
    };
}

// ─── COSE_Mac0 (RFC 9052 §6) ────────────────────────────────────────────────

/** Tag 17 header byte: major type 6 (tag) with value 17 = 0xd1 */
const TAG_17_HEADER = new Uint8Array([0xd1]);

/** COSE MAC algorithm: HMAC 256/256 (IANA value 5) */
export const COSE_MAC_ALG = {
    /** HMAC w/ SHA-256 (256-bit key, 256-bit tag) */
    HMAC_256_256: 5,
} as const;

/** Options for creating a COSE_Mac0 */
export interface Mac0CreateOptions {
    /** Payload to MAC (CBOR-encoded content) */
    payload: Uint8Array;
    /** HMAC-SHA-256 key (raw symmetric key from ECDH + HKDF) */
    macKey: CryptoKey;
    /** Additional protected headers */
    extraProtectedHeaders?: Map<number, unknown>;
    /** Unprotected headers */
    unprotectedHeaders?: Map<number, unknown>;
    /** External additional authenticated data (default: empty) */
    externalAad?: Uint8Array;
}

/** Result of COSE_Mac0 verification */
export interface Mac0VerifyResult {
    /** Whether the MAC tag is valid */
    valid: boolean;
    /** Decoded payload (if MAC valid) */
    payload: Uint8Array | null;
    /** Decoded protected headers */
    protectedHeaders: CoseHeaderMap;
}

/** Decoded COSE_Mac0 structure */
export interface CoseMac0Structure {
    protectedHeaders: Uint8Array;
    decodedProtectedHeaders: CoseHeaderMap;
    unprotectedHeaders: CoseHeaderMap;
    payload: Uint8Array | null;
    tag: Uint8Array;
}

/**
 * Build the MAC_structure for COSE_Mac0 signing/verification.
 *
 * MAC_structure = [
 *   context : "MAC0",
 *   body_protected : bstr,
 *   external_aad : bstr,
 *   payload : bstr
 * ]
 */
function buildMacStructure0(
    protectedHeaderBytes: Uint8Array,
    payload: Uint8Array,
    externalAad: Uint8Array = new Uint8Array(0),
): Uint8Array {
    return encode(['MAC0', protectedHeaderBytes, externalAad, payload]);
}

/**
 * Create a COSE_Mac0 structure.
 *
 * Returns CBOR-encoded COSE_Mac0 tagged with Tag 17.
 * Algorithm: HMAC 256/256.
 */
export async function createMac0(opts: Mac0CreateOptions): Promise<Uint8Array> {
    const { payload, macKey, externalAad } = opts;

    const protectedMap = new Map<number, unknown>();
    protectedMap.set(COSE_HEADER.ALG, COSE_MAC_ALG.HMAC_256_256);
    if (opts.extraProtectedHeaders) {
        for (const [k, v] of opts.extraProtectedHeaders) {
            protectedMap.set(k, v);
        }
    }

    const protectedHeaderBytes = encodeProtectedHeaders(protectedMap);
    const macStructure = buildMacStructure0(protectedHeaderBytes, payload, externalAad);

    const tagBuffer = await crypto.subtle.sign(
        'HMAC',
        macKey,
        toArrayBuffer(macStructure),
    );
    const tag = new Uint8Array(tagBuffer);

    const unprotected = opts.unprotectedHeaders ?? new Map<number, unknown>();
    const coseArray = [protectedHeaderBytes, unprotected, payload, tag];

    const arrayBytes = encode(coseArray);
    const result = new Uint8Array(TAG_17_HEADER.length + arrayBytes.length);
    result.set(TAG_17_HEADER, 0);
    result.set(arrayBytes, TAG_17_HEADER.length);
    return result;
}

/**
 * Decode a COSE_Mac0 structure without verifying the tag.
 */
export function decodeCoseMac0(coseMac0Bytes: Uint8Array): CoseMac0Structure {
    const decoded = coseDecode<unknown[]>(coseMac0Bytes);

    if (!Array.isArray(decoded) || decoded.length !== 4) {
        throw new Error('Invalid COSE_Mac0: expected 4-element array');
    }

    const [protectedHeaderBytes, unprotectedRaw, payloadRaw, tagRaw] = decoded;

    if (!(protectedHeaderBytes instanceof Uint8Array)) {
        throw new Error('Invalid COSE_Mac0: protected headers must be a byte string');
    }
    if (!(tagRaw instanceof Uint8Array)) {
        throw new Error('Invalid COSE_Mac0: tag must be a byte string');
    }

    const protectedMap: CoseHeaderMap = protectedHeaderBytes.length > 0
        ? coseDecode<CoseHeaderMap>(protectedHeaderBytes)
        : new Map<number, unknown>();

    const unprotectedHeaders: CoseHeaderMap = unprotectedRaw instanceof Map
        ? unprotectedRaw
        : new Map<number, unknown>();

    const payload = payloadRaw instanceof Uint8Array ? payloadRaw
        : payloadRaw === null ? null
        : null;

    return {
        protectedHeaders: protectedHeaderBytes,
        decodedProtectedHeaders: protectedMap,
        unprotectedHeaders,
        payload,
        tag: tagRaw,
    };
}

/**
 * Verify a COSE_Mac0 structure.
 *
 * Accepts CBOR-encoded COSE_Mac0 (with or without Tag 17).
 */
export async function verifyMac0(
    coseMac0Bytes: Uint8Array,
    macKey: CryptoKey,
    externalAad: Uint8Array = new Uint8Array(0),
): Promise<Mac0VerifyResult> {
    const parsed = decodeCoseMac0(coseMac0Bytes);

    const alg = parsed.decodedProtectedHeaders.get(COSE_HEADER.ALG);
    if (alg !== COSE_MAC_ALG.HMAC_256_256) {
        return { valid: false, payload: null, protectedHeaders: parsed.decodedProtectedHeaders };
    }

    const macStructure = buildMacStructure0(
        parsed.protectedHeaders,
        parsed.payload ?? new Uint8Array(0),
        externalAad,
    );

    const valid = await crypto.subtle.verify(
        'HMAC',
        macKey,
        toArrayBuffer(parsed.tag),
        toArrayBuffer(macStructure),
    );

    return {
        valid,
        payload: valid ? parsed.payload : null,
        protectedHeaders: parsed.decodedProtectedHeaders,
    };
}

// ─── ECDH Session Key Derivation (ISO 18013-5 §9.1.1.5) ────────────────────

/**
 * Derive a shared HMAC key from ECDH key agreement.
 *
 * ISO 18013-5 uses ECDH (P-256) between device and reader, then
 * derives a symmetric key for COSE_Mac0 via HKDF-SHA-256.
 *
 * @param privateKey - One party's ECDH private key
 * @param publicKey - Other party's ECDH public key
 * @param salt - HKDF salt (typically session transcript hash or empty)
 * @param info - HKDF info (typically "EMacKey" per ISO 18013-5)
 * @returns CryptoKey suitable for HMAC-SHA-256
 */
export async function deriveSessionMacKey(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    salt: Uint8Array = new Uint8Array(32),
    info: Uint8Array = new TextEncoder().encode('EMacKey'),
): Promise<CryptoKey> {
    // ECDH key agreement → shared secret
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: publicKey },
        privateKey,
        256,
    );

    // Import shared secret as HKDF base key
    const hkdfKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        'HKDF',
        false,
        ['deriveKey'],
    );

    // HKDF → HMAC-SHA-256 key
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: toArrayBuffer(salt), info: toArrayBuffer(info) },
        hkdfKey,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify'],
    );
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Encode a protected header map to CBOR bytes.
 * COSE requires protected headers to be serialized as a CBOR byte string
 * containing a CBOR-encoded map.
 */
function encodeProtectedHeaders(headers: Map<number, unknown>): Uint8Array {
    if (headers.size === 0) {
        return new Uint8Array(0);
    }
    return encode(headers);
}
