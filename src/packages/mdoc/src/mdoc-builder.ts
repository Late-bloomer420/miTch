/**
 * @module @askmi/mdoc/mdoc-builder
 *
 * ISO 18013-5 mdoc Document Builder — Issuance Pipeline.
 *
 * Constructs mdoc documents from claims for hybrid issuance (OID4VCI).
 * Complements the existing verification pipeline (verifier.ts).
 *
 * Pipeline:
 * 1. Build IssuerSignedItems from claim key-value pairs
 * 2. Compute digests for each item → MSO valueDigests
 * 3. Assemble MobileSecurityObject with device key + validity
 * 4. Sign MSO with COSE_Sign1 → issuerAuth
 * 5. Package as MdocDocument (issuerSigned only; deviceSigned added at presentation)
 */

import type {
  IssuerSignedItem,
  MobileSecurityObject,
  MdocDocument,
  IssuerSigned,
  ValidityInfo,
  DigestAlgorithm,
  NameSpace,
} from './mdoc-types.js';
import { digestItem } from './mso.js';
import { encode } from './cbor.js';
import { createSign1 } from './cose.js';
import { exportCoseKey } from './cose-key.js';

// ─── Types ───────────────────────────────────────────────────────────

/** Claims for a single namespace, keyed by element identifier. */
export type NamespaceClaims = Record<string, unknown>;

/** Options for building an mdoc document. */
export interface MdocBuildOptions {
  /** Document type (e.g., "org.iso.18013.5.1.mDL"). */
  docType: string;
  /** Claims per namespace. */
  nameSpaces: Record<string, NamespaceClaims>;
  /** Issuer's private key for COSE_Sign1 signing (ES256). */
  issuerPrivateKey: CryptoKey;
  /** Holder's device public key (bound in the MSO). */
  devicePublicKey: CryptoKey;
  /** Validity period for the MSO. */
  validityInfo: ValidityInfo;
  /** Digest algorithm (default: SHA-256). */
  digestAlgorithm?: DigestAlgorithm;
  /** MSO version (default: "1.0"). */
  version?: string;
  /** Extra COSE protected headers (e.g., x5chain). */
  extraProtectedHeaders?: Map<number, unknown>;
}

/** Result of mdoc document construction. */
export interface MdocBuildResult {
  /** The complete mdoc document (without deviceSigned — added at presentation). */
  document: MdocDocument;
  /** Raw CBOR bytes of the entire document (for transport/storage). */
  documentCbor: Uint8Array;
  /** The MSO that was signed (for diagnostics). */
  mso: MobileSecurityObject;
}

// ─── Builder Functions ───────────────────────────────────────────────

/**
 * Build IssuerSignedItems from claim key-value pairs.
 * Each item gets a fresh random salt (16 bytes) and sequential digestID.
 */
export function buildIssuerSignedItems(
  claims: NamespaceClaims,
  startDigestID: number = 0,
): IssuerSignedItem[] {
  const items: IssuerSignedItem[] = [];
  let digestID = startDigestID;

  for (const [elementIdentifier, elementValue] of Object.entries(claims)) {
    items.push({
      digestID,
      random: crypto.getRandomValues(new Uint8Array(16)),
      elementIdentifier,
      elementValue,
    });
    digestID++;
  }

  return items;
}

/**
 * Build a MobileSecurityObject from namespace items.
 * Computes SHA-256 digests for all items.
 */
export async function buildMobileSecurityObject(opts: {
  docType: string;
  nameSpaceItems: Map<NameSpace, IssuerSignedItem[]>;
  devicePublicKey: CryptoKey;
  validityInfo: ValidityInfo;
  digestAlgorithm?: DigestAlgorithm;
  version?: string;
}): Promise<MobileSecurityObject> {
  const alg = opts.digestAlgorithm ?? 'SHA-256';
  const valueDigests = new Map<NameSpace, Map<number, Uint8Array>>();

  for (const [ns, items] of opts.nameSpaceItems) {
    const digestMap = new Map<number, Uint8Array>();
    for (const item of items) {
      digestMap.set(item.digestID, await digestItem(item, alg));
    }
    valueDigests.set(ns, digestMap);
  }

  const deviceKey = await exportCoseKey(opts.devicePublicKey);

  return {
    version: opts.version ?? '1.0',
    digestAlgorithm: alg,
    valueDigests,
    deviceKeyInfo: { deviceKey },
    docType: opts.docType,
    validityInfo: opts.validityInfo,
  };
}

/**
 * Sign an MSO with the issuer's private key (COSE_Sign1).
 * Returns the raw issuerAuth bytes.
 */
export async function signMobileSecurityObject(
  mso: MobileSecurityObject,
  issuerPrivateKey: CryptoKey,
  extraProtectedHeaders?: Map<number, unknown>,
): Promise<Uint8Array> {
  return createSign1({
    payload: encode(mso),
    privateKey: issuerPrivateKey,
    extraProtectedHeaders,
  });
}

/**
 * Build a complete mdoc document ready for issuance.
 *
 * This is the main entry point for hybrid issuance. The returned document
 * contains only issuerSigned (no deviceSigned — that's added by the holder
 * at presentation time).
 *
 * @returns MdocBuildResult with document, CBOR bytes, and MSO
 */
export async function buildMdocDocument(
  opts: MdocBuildOptions,
): Promise<MdocBuildResult> {
  const alg = opts.digestAlgorithm ?? 'SHA-256';

  // 1. Build IssuerSignedItems per namespace
  const nameSpaceItems = new Map<NameSpace, IssuerSignedItem[]>();
  for (const [ns, claims] of Object.entries(opts.nameSpaces)) {
    const existingCount = nameSpaceItems.size > 0
      ? Array.from(nameSpaceItems.values()).reduce((sum, items) => sum + items.length, 0)
      : 0;
    nameSpaceItems.set(ns, buildIssuerSignedItems(claims, existingCount));
  }

  // 2. Build MSO
  const mso = await buildMobileSecurityObject({
    docType: opts.docType,
    nameSpaceItems,
    devicePublicKey: opts.devicePublicKey,
    validityInfo: opts.validityInfo,
    digestAlgorithm: alg,
    version: opts.version,
  });

  // 3. Sign MSO → issuerAuth
  const issuerAuth = await signMobileSecurityObject(
    mso,
    opts.issuerPrivateKey,
    opts.extraProtectedHeaders,
  );

  // 4. Assemble IssuerSigned
  const issuerSigned: IssuerSigned = {
    nameSpaces: nameSpaceItems,
    issuerAuth,
  };

  // 5. Package as MdocDocument
  const document: MdocDocument = {
    docType: opts.docType,
    issuerSigned,
  };

  // 6. Encode to CBOR
  const documentCbor = encode(document);

  return { document, documentCbor, mso };
}

/**
 * Build a DeviceResponse structure containing one or more mdoc documents.
 * ISO 18013-5 §8.3.
 */
export function buildDeviceResponse(documents: MdocDocument[]): Uint8Array {
  const response: Map<string, unknown> = new Map();
  response.set('version', '1.0');
  response.set('documents', documents);
  response.set('status', 0); // OK

  return encode(response);
}
