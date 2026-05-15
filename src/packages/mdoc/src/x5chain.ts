/**
 * @module @mitch/mdoc/x5chain
 *
 * ISO 18013-5 / RFC 9360 — x5chain (header label 33) extraction
 * from COSE_Sign1 protected/unprotected headers.
 *
 * Extracts the issuer's X.509 certificate chain and imports the
 * leaf certificate's public key for issuer signature verification.
 *
 * Scope:
 * - Extract x5chain from COSE headers (single cert or array)
 * - Import leaf cert public key via WebCrypto (ECDSA P-256)
 * - Trust anchor verification via callback (pluggable)
 *
 * Fail-closed: missing x5chain, unsupported key → error.
 */

import type { CoseHeaderMap } from './cose.js';
import { toArrayBuffer } from './util.js';

/** COSE header label for x5chain (IANA COSE Header Parameters) */
export const COSE_HEADER_X5CHAIN = 33;

/** Parsed certificate chain result. */
export interface X5ChainResult {
  /** Leaf certificate (DER bytes) — the issuer's signing cert */
  leaf: Uint8Array;
  /** Full chain (DER bytes array), leaf first */
  chain: Uint8Array[];
}

/** Trust anchor verification callback. */
export type TrustAnchorVerifier = (chain: Uint8Array[]) => Promise<boolean>;

/**
 * Extract x5chain from COSE_Sign1 protected and/or unprotected headers.
 *
 * Per RFC 9360 §2: x5chain (label 33) contains either:
 * - A single certificate (bstr)
 * - An ordered array of certificates (array of bstr), leaf first
 *
 * Protected headers take precedence over unprotected.
 * Fail-closed: missing x5chain → throws.
 */
export function extractX5Chain(
  protectedHeaders: CoseHeaderMap,
  unprotectedHeaders: CoseHeaderMap
): X5ChainResult {
  const x5chain = protectedHeaders.get(COSE_HEADER_X5CHAIN)
    ?? unprotectedHeaders.get(COSE_HEADER_X5CHAIN);

  if (!x5chain) {
    throw new Error('No x5chain (header 33) found in COSE headers');
  }

  // Single cert (bstr)
  if (x5chain instanceof Uint8Array) {
    return { leaf: x5chain, chain: [x5chain] };
  }

  // Array of certs
  if (Array.isArray(x5chain) && x5chain.length > 0) {
    for (let i = 0; i < x5chain.length; i++) {
      if (!(x5chain[i] instanceof Uint8Array)) {
        throw new Error(`x5chain[${i}] is not a byte string`);
      }
    }
    return { leaf: x5chain[0], chain: x5chain as Uint8Array[] };
  }

  throw new Error('x5chain has invalid format (expected bstr or array of bstr)');
}

/**
 * Minimal ASN.1 DER parser — extract the SubjectPublicKeyInfo (SPKI) from
 * an X.509 certificate for WebCrypto import.
 *
 * X.509 structure (simplified):
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate SEQUENCE {
 *       version [0] EXPLICIT ...,
 *       serialNumber INTEGER,
 *       signature AlgorithmIdentifier,
 *       issuer Name,
 *       validity SEQUENCE,
 *       subject Name,
 *       subjectPublicKeyInfo SubjectPublicKeyInfo, ← we extract this
 *       ...
 *     }
 *   }
 *
 * We find the SPKI by counting SEQUENCE/tagged elements in tbsCertificate.
 */
export function extractSpkiFromCert(certDer: Uint8Array): Uint8Array {
  let offset = 0;

  // Read a DER tag+length, return { tag, length, headerSize }
  function readTL(pos: number): { tag: number; length: number; headerSize: number } {
    if (pos >= certDer.length) throw new Error('DER: unexpected end of data');
    const tag = certDer[pos];
    let lenByte = certDer[pos + 1];
    let length: number;
    let headerSize: number;

    if (lenByte < 0x80) {
      length = lenByte;
      headerSize = 2;
    } else {
      const numBytes = lenByte & 0x7f;
      if (numBytes === 0 || numBytes > 4) {
        throw new Error(`DER: unsupported length encoding (${numBytes} bytes)`);
      }
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | certDer[pos + 2 + i];
      }
      headerSize = 2 + numBytes;
    }

    return { tag, length, headerSize };
  }

  // Skip a complete TLV element, return position after it
  function skipTLV(pos: number): number {
    const { length, headerSize } = readTL(pos);
    return pos + headerSize + length;
  }

  // Get the raw bytes of a TLV element (tag + length + value)
  function getTLVBytes(pos: number): Uint8Array {
    const { length, headerSize } = readTL(pos);
    return certDer.slice(pos, pos + headerSize + length);
  }

  // Certificate SEQUENCE
  const certSeq = readTL(offset);
  if ((certSeq.tag & 0x1f) !== 0x10) throw new Error('DER: expected SEQUENCE for Certificate');
  offset += certSeq.headerSize;

  // tbsCertificate SEQUENCE
  const tbsSeq = readTL(offset);
  if ((tbsSeq.tag & 0x1f) !== 0x10) throw new Error('DER: expected SEQUENCE for tbsCertificate');
  let tbsOffset = offset + tbsSeq.headerSize;

  // Field 0: version [0] EXPLICIT (optional, context tag 0xA0)
  let fieldTag = readTL(tbsOffset);
  if (fieldTag.tag === 0xa0) {
    tbsOffset = skipTLV(tbsOffset); // skip version
    fieldTag = readTL(tbsOffset);
  }

  // Field 1: serialNumber INTEGER
  tbsOffset = skipTLV(tbsOffset);

  // Field 2: signature AlgorithmIdentifier SEQUENCE
  tbsOffset = skipTLV(tbsOffset);

  // Field 3: issuer Name SEQUENCE
  tbsOffset = skipTLV(tbsOffset);

  // Field 4: validity SEQUENCE
  tbsOffset = skipTLV(tbsOffset);

  // Field 5: subject Name SEQUENCE
  tbsOffset = skipTLV(tbsOffset);

  // Field 6: subjectPublicKeyInfo SEQUENCE — this is what we want
  return getTLVBytes(tbsOffset);
}

/**
 * Import the leaf certificate's public key as a WebCrypto CryptoKey.
 *
 * Extracts SPKI from the DER certificate and imports it for ECDSA P-256 verification.
 * Fail-closed: unsupported algorithm → throws.
 *
 * @param certDer - DER-encoded X.509 certificate
 * @returns WebCrypto public key for signature verification
 */
export async function importPublicKeyFromCert(certDer: Uint8Array): Promise<CryptoKey> {
  const spki = extractSpkiFromCert(certDer);

  // Try ECDSA P-256 first (mandatory for ISO 18013-5)
  try {
    return await crypto.subtle.importKey(
      'spki',
      toArrayBuffer(spki),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  } catch {
    // Could be a different curve or algorithm
    throw new Error('Failed to import public key from certificate (only ECDSA P-256 supported)');
  }
}
