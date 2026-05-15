/**
 * @module @mitch/mdoc/mso
 *
 * ISO 18013-5 §8.2.2.1 — MSO Digest Verification.
 *
 * Verifies that disclosed IssuerSignedItems match the digests
 * in the MobileSecurityObject. Fail-closed: any mismatch → invalid.
 */

import type {
  DigestAlgorithm,
  IssuerSignedItem,
  MobileSecurityObject,
  NameSpace,
} from './mdoc-types.js';
import { encode, encodeEmbeddedCbor, decodeMdoc } from './cbor.js';
import { verifySign1 } from './cose.js';
import type { Sign1VerifyResult } from './cose.js';
import { mapGet, toArrayBuffer } from './util.js';

/** Maps ISO 18013-5 digest algorithm names to WebCrypto algorithm identifiers. */
const DIGEST_ALG_MAP: Record<DigestAlgorithm, string> = {
  'SHA-256': 'SHA-256',
  'SHA-384': 'SHA-384',
  'SHA-512': 'SHA-512',
};

/** Detail about an invalid item for diagnostics. */
export interface InvalidDigestItem {
  namespace: string;
  digestId: number;
  reason: string;
}

/** Result of MSO digest verification. */
export interface MsoDigestResult {
  valid: boolean;
  invalidItems?: InvalidDigestItem[];
}

/** Result of full MSO extraction + verification. */
export interface MsoVerifyResult {
  valid: boolean;
  mso?: MobileSecurityObject;
  reason?: string;
}

/**
 * Compute the digest of an IssuerSignedItem per ISO 18013-5 §9.1.2.4.
 *
 * The item is CBOR-encoded, wrapped in Tag 24 (embedded CBOR),
 * then hashed with the specified algorithm.
 */
export async function digestItem(
  item: IssuerSignedItem,
  alg: DigestAlgorithm
): Promise<Uint8Array> {
  const webcryptoAlg = DIGEST_ALG_MAP[alg];
  if (!webcryptoAlg) {
    throw new Error(`Unsupported digest algorithm: ${alg}`);
  }

  // ISO 18013-5: IssuerSignedItem is CBOR-encoded, then wrapped in Tag 24
  const tag24Bytes = encodeEmbeddedCbor(item);
  const hashBuffer = await crypto.subtle.digest(webcryptoAlg, toArrayBuffer(tag24Bytes));
  return new Uint8Array(hashBuffer);
}

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing side-channels on digest comparison.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Verify that disclosed IssuerSignedItems match the digests in the MSO.
 *
 * Per ISO 18013-5 §8.2.2.1:
 * - For each disclosed item in each namespace, compute its digest
 * - Compare against the corresponding entry in MSO.valueDigests
 * - Fail-closed: missing digest, wrong digest → invalid
 *
 * Items in MSO.valueDigests that are NOT disclosed are ignored
 * (selective disclosure allows partial presentation).
 */
export async function verifyMsoDigests(
  mso: MobileSecurityObject,
  disclosedNamespaces: Map<NameSpace, IssuerSignedItem[]>
): Promise<MsoDigestResult> {
  const invalidItems: InvalidDigestItem[] = [];

  for (const [namespace, items] of disclosedNamespaces) {
    const digestMap = mapGet(mso.valueDigests, namespace);

    if (!digestMap) {
      // Namespace not in MSO — all items in this namespace are invalid
      for (const item of items) {
        invalidItems.push({
          namespace,
          digestId: item.digestID,
          reason: `Namespace "${namespace}" not found in MSO valueDigests`,
        });
      }
      continue;
    }

    for (const item of items) {
      const expectedDigest = mapGet(digestMap, item.digestID);

      if (!expectedDigest) {
        invalidItems.push({
          namespace,
          digestId: item.digestID,
          reason: `digestID ${item.digestID} not found in MSO for namespace "${namespace}"`,
        });
        continue;
      }

      const computedDigest = await digestItem(item, mso.digestAlgorithm);

      if (!bytesEqual(expectedDigest, computedDigest)) {
        invalidItems.push({
          namespace,
          digestId: item.digestID,
          reason: `Digest mismatch for digestID ${item.digestID} in namespace "${namespace}"`,
        });
      }
    }
  }

  if (invalidItems.length > 0) {
    return { valid: false, invalidItems };
  }

  return { valid: true };
}

/**
 * Full E2E: Extract MSO from COSE_Sign1 envelope, verify signature,
 * then verify disclosed item digests.
 *
 * 1. Verify COSE_Sign1 signature (issuer authenticity)
 * 2. Decode MSO from payload
 * 3. Verify item digests against MSO
 *
 * Fail-closed: signature invalid OR digest mismatch → invalid.
 */
export async function extractAndVerifyMso(
  issuerAuth: Uint8Array,
  disclosedNamespaces: Map<NameSpace, IssuerSignedItem[]>,
  issuerPublicKey: CryptoKey
): Promise<MsoVerifyResult> {
  // Step 1: Verify COSE_Sign1 signature
  let signResult: Sign1VerifyResult;
  try {
    signResult = await verifySign1(issuerAuth, issuerPublicKey);
  } catch {
    return { valid: false, reason: 'COSE_Sign1 decoding failed' };
  }

  if (!signResult.valid) {
    return { valid: false, reason: 'Issuer signature invalid' };
  }

  if (!signResult.payload) {
    return { valid: false, reason: 'COSE_Sign1 payload is null' };
  }

  // Step 2: Decode MSO from CBOR payload (useMaps for integer-keyed COSE/digest maps)
  let mso: MobileSecurityObject;
  try {
    const decoded = decodeMdoc<Map<string, unknown>>(signResult.payload);
    mso = mapToMso(decoded);
  } catch {
    return { valid: false, reason: 'MSO payload is not valid CBOR' };
  }

  // Step 3: Verify digests
  const digestResult = await verifyMsoDigests(mso, disclosedNamespaces);

  if (!digestResult.valid) {
    return {
      valid: false,
      mso,
      reason: `Digest verification failed: ${digestResult.invalidItems![0].reason}`,
    };
  }

  return { valid: true, mso };
}

/**
 * Convert a decoded CBOR Map to a typed MobileSecurityObject.
 * CBOR decode with useMaps returns Maps — we extract the MSO fields.
 */
function mapToMso(m: Map<string, unknown>): MobileSecurityObject {
  return {
    version: m.get('version') as string,
    digestAlgorithm: m.get('digestAlgorithm') as DigestAlgorithm,
    valueDigests: normalizeValueDigests(m.get('valueDigests')),
    deviceKeyInfo: mapToDeviceKeyInfo(m.get('deviceKeyInfo')),
    docType: m.get('docType') as string,
    validityInfo: mapToValidityInfo(m.get('validityInfo')),
  };
}

/**
 * Normalize valueDigests to Map<string, Map<number, Uint8Array>>.
 * CBOR decode may return string keys for digest IDs (when the MSO was
 * encoded from a plain object), so we coerce keys to numbers.
 */
function normalizeValueDigests(raw: unknown): MobileSecurityObject['valueDigests'] {
  const result = new Map<NameSpace, Map<number, Uint8Array>>();
  if (!(raw instanceof Map)) return result;

  for (const [ns, digestMap] of raw) {
    const normalized = new Map<number, Uint8Array>();
    if (digestMap instanceof Map) {
      for (const [key, value] of digestMap) {
        normalized.set(typeof key === 'string' ? parseInt(key, 10) : key, value as Uint8Array);
      }
    }
    result.set(ns as string, normalized);
  }
  return result;
}

function mapToDeviceKeyInfo(raw: unknown): MobileSecurityObject['deviceKeyInfo'] {
  if (raw instanceof Map) {
    return { deviceKey: raw.get('deviceKey') as Map<number, unknown> };
  }
  const obj = raw as Record<string, unknown>;
  return { deviceKey: obj?.deviceKey as Map<number, unknown> };
}

function mapToValidityInfo(raw: unknown): MobileSecurityObject['validityInfo'] {
  if (raw instanceof Map) {
    return {
      signed: raw.get('signed') as Date,
      validFrom: raw.get('validFrom') as Date,
      validUntil: raw.get('validUntil') as Date,
      expectedUpdate: raw.get('expectedUpdate') as Date | undefined,
    };
  }
  const obj = raw as Record<string, unknown>;
  return {
    signed: obj?.signed as Date,
    validFrom: obj?.validFrom as Date,
    validUntil: obj?.validUntil as Date,
    expectedUpdate: obj?.expectedUpdate as Date | undefined,
  };
}
