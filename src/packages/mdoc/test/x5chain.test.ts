import { describe, test, expect, beforeAll } from 'vitest';
import {
  extractX5Chain,
  importPublicKeyFromCert,
  extractSpkiFromCert,
  COSE_HEADER_X5CHAIN,
} from '../src/x5chain';
import type { CoseHeaderMap } from '../src/cose';

// ─── Test helpers ───────────────────────────────────────────────────────────

/**
 * Generate a self-signed X.509 certificate for testing.
 * We use a P-256 key and build a minimal DER cert.
 */
let testKeyPair: CryptoKeyPair;
let testCertDer: Uint8Array;

/** Build a minimal self-signed X.509 v3 certificate in DER format. */
async function buildSelfSignedCert(keyPair: CryptoKeyPair): Promise<Uint8Array> {
  const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const spki = new Uint8Array(spkiBuffer);

  // Minimal ASN.1 DER X.509 certificate
  // TBSCertificate structure
  const version = asn1Explicit(0, asn1Integer(new Uint8Array([0x02]))); // v3
  const serialNumber = asn1Integer(new Uint8Array([0x01]));
  const sigAlg = ecdsaSha256AlgId();
  const issuer = asn1Sequence([
    asn1Set([
      asn1Sequence([
        asn1Oid([0x55, 0x04, 0x03]), // CN OID
        asn1Utf8('Test Issuer'),
      ]),
    ]),
  ]);
  const validity = asn1Sequence([asn1UtcTime('260101000000Z'), asn1UtcTime('270101000000Z')]);
  const subject = issuer; // self-signed
  const tbsBody = [version, serialNumber, sigAlg, issuer, validity, subject, spki];
  const tbs = asn1Sequence(tbsBody.map((b) => ({ raw: b })));

  // Sign TBS with private key
  const sigBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    tbs
  );
  const sigBytes = new Uint8Array(sigBuffer);

  // Wrap signature in BIT STRING
  const sigBitString = asn1BitString(sigBytes);

  // Certificate = SEQUENCE { tbs, sigAlg, sig }
  return asn1Sequence([{ raw: tbs }, { raw: sigAlg }, { raw: sigBitString }]);
}

// ─── Minimal ASN.1 DER builders ─────────────────────────────────────────────

function asn1Length(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function asn1Wrap(tag: number, content: Uint8Array): Uint8Array {
  const len = asn1Length(content.length);
  const result = new Uint8Array(1 + len.length + content.length);
  result[0] = tag;
  result.set(len, 1);
  result.set(content, 1 + len.length);
  return result;
}

function asn1Sequence(items: (Uint8Array | { raw: Uint8Array })[]): Uint8Array {
  const parts = items.map((i) => (i instanceof Uint8Array ? i : i.raw));
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const body = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    body.set(p, offset);
    offset += p.length;
  }
  return asn1Wrap(0x30, body);
}

function asn1Set(items: Uint8Array[]): Uint8Array {
  const totalLen = items.reduce((sum, p) => sum + p.length, 0);
  const body = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of items) {
    body.set(p, offset);
    offset += p.length;
  }
  return asn1Wrap(0x31, body);
}

function asn1Integer(value: Uint8Array): Uint8Array {
  // Ensure positive (leading 0 if high bit set)
  if (value[0] & 0x80) {
    const padded = new Uint8Array(value.length + 1);
    padded.set(value, 1);
    return asn1Wrap(0x02, padded);
  }
  return asn1Wrap(0x02, value);
}

function asn1Oid(oidBytes: number[]): Uint8Array {
  return asn1Wrap(0x06, new Uint8Array(oidBytes));
}

function asn1Utf8(str: string): Uint8Array {
  return asn1Wrap(0x0c, new TextEncoder().encode(str));
}

function asn1UtcTime(time: string): Uint8Array {
  return asn1Wrap(0x17, new TextEncoder().encode(time));
}

function asn1BitString(data: Uint8Array): Uint8Array {
  const content = new Uint8Array(data.length + 1);
  content[0] = 0x00; // no unused bits
  content.set(data, 1);
  return asn1Wrap(0x03, content);
}

function asn1Explicit(tagNum: number, content: Uint8Array): Uint8Array {
  return asn1Wrap(0xa0 | tagNum, content);
}

function ecdsaSha256AlgId(): Uint8Array {
  // SEQUENCE { OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256) }
  const oid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
  return asn1Wrap(0x30, oid);
}

// ─── Setup ──────────────────────────────────────────────────────────────────

beforeAll(async () => {
  testKeyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  testCertDer = await buildSelfSignedCert(testKeyPair);
});

// ─── extractX5Chain ─────────────────────────────────────────────────────────

describe('extractX5Chain', () => {
  test('extracts single cert from protected headers', () => {
    const protectedHeaders = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, testCertDer]]);
    const unprotected = new Map<number, unknown>();
    const result = extractX5Chain(protectedHeaders, unprotected);
    expect(result.leaf).toBe(testCertDer);
    expect(result.chain).toHaveLength(1);
  });

  test('extracts cert array from protected headers', () => {
    const chain = [testCertDer, new Uint8Array([0xca, 0xfe])];
    const protectedHeaders = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, chain]]);
    const unprotected = new Map<number, unknown>();
    const result = extractX5Chain(protectedHeaders, unprotected);
    expect(result.leaf).toBe(testCertDer);
    expect(result.chain).toHaveLength(2);
  });

  test('falls back to unprotected headers', () => {
    const protectedHeaders = new Map<number, unknown>();
    const unprotected = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, testCertDer]]);
    const result = extractX5Chain(protectedHeaders, unprotected);
    expect(result.leaf).toBe(testCertDer);
  });

  test('protected takes precedence over unprotected', () => {
    const otherCert = new Uint8Array([0xde, 0xad]);
    const protectedHeaders = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, testCertDer]]);
    const unprotected = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, otherCert]]);
    const result = extractX5Chain(protectedHeaders, unprotected);
    expect(result.leaf).toBe(testCertDer);
  });

  test('throws when x5chain missing', () => {
    expect(() => extractX5Chain(new Map(), new Map())).toThrow('No x5chain');
  });

  test('throws on invalid format (number)', () => {
    const headers = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, 42]]);
    expect(() => extractX5Chain(headers, new Map())).toThrow('invalid format');
  });

  test('throws on empty array', () => {
    const headers = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, []]]);
    expect(() => extractX5Chain(headers, new Map())).toThrow('invalid format');
  });

  test('throws when array contains non-bstr', () => {
    const headers = new Map<number, unknown>([[COSE_HEADER_X5CHAIN, [testCertDer, 42]]]);
    expect(() => extractX5Chain(headers, new Map())).toThrow('not a byte string');
  });
});

// ─── extractSpkiFromCert ────────────────────────────────────────────────────

describe('extractSpkiFromCert', () => {
  test('extracts SPKI from self-signed cert', () => {
    const spki = extractSpkiFromCert(testCertDer);
    // SPKI should be a SEQUENCE (tag 0x30)
    expect(spki[0]).toBe(0x30);
    // Should be non-trivial length (P-256 SPKI is ~91 bytes)
    expect(spki.length).toBeGreaterThan(50);
    expect(spki.length).toBeLessThan(200);
  });

  test('throws on invalid DER', () => {
    expect(() => extractSpkiFromCert(new Uint8Array([0x00, 0x01]))).toThrow();
  });
});

// ─── importPublicKeyFromCert ────────────────────────────────────────────────

describe('importPublicKeyFromCert', () => {
  test('imports P-256 public key from self-signed cert', async () => {
    const pubKey = await importPublicKeyFromCert(testCertDer);
    expect(pubKey.type).toBe('public');
    expect(pubKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
  });

  test('imported key verifies signatures from the same keypair', async () => {
    const pubKey = await importPublicKeyFromCert(testCertDer);
    const data = new Uint8Array([1, 2, 3, 4]);
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      testKeyPair.privateKey,
      data
    );
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, data);
    expect(valid).toBe(true);
  });

  test('imported key rejects signatures from different keypair', async () => {
    const otherKey = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
    const pubKey = await importPublicKeyFromCert(testCertDer);
    const data = new Uint8Array([1, 2, 3, 4]);
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      otherKey.privateKey,
      data
    );
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, data);
    expect(valid).toBe(false);
  });
});
