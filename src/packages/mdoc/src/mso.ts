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
import { encode, encodeEmbeddedCbor, decode } from './cbor.js';
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

  // Step 2: Decode MSO from CBOR payload
  let mso: MobileSecurityObject;
  try {
    mso = decode<MobileSecurityObject>(signResult.payload);
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
