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
const COSE_DECODE_OPTIONS = {
    useMaps: true,
    tags: {
        [CBOR_TAGS.COSE_SIGN1]: (value: unknown) => value,
        [CBOR_TAGS.COSE_MAC0]: (value: unknown) => value,
        [CBOR_TAGS.EMBEDDED_CBOR]: (innerBytes: Uint8Array) => {
            return cborgDecode(innerBytes, COSE_DECODE_OPTIONS);
        },
    } as Record<number, (value: unknown) => unknown>,
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

/** COSE_Sign1 CBOR Tag (RFC 9052 §4.2) */
const COSE_SIGN1_TAG = 18;

/** Tag 18 header bytes: major type 6 (tag) with value 18 = 0xd2 */
const TAG_18_HEADER = new Uint8Array([0xd2]);

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
        sigStructure,
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
        parsed.signature,
        sigStructure,
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
