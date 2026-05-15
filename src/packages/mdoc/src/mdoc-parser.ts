/**
 * @module @mitch/mdoc/mdoc-parser
 *
 * ISO 18013-5 — Parse CBOR-encoded mdoc DeviceResponse into typed structures.
 *
 * DeviceResponse = {
 *   version: tstr,
 *   documents: [+ Document],
 *   status: uint
 * }
 *
 * Document = {
 *   docType: tstr,
 *   issuerSigned: IssuerSigned,
 *   deviceSigned: DeviceSigned
 * }
 *
 * Fail-closed: malformed input → throws.
 */

import type {
  MdocDocument,
  IssuerSigned,
  DeviceSigned,
  IssuerSignedItem,
  NameSpace,
  DeviceAuth,
  DataElementValue,
} from './mdoc-types.js';
import { decode, decodeMdoc } from './cbor.js';
import { mapGet } from './util.js';

/** Parsed DeviceResponse structure. */
export interface DeviceResponse {
  version: string;
  documents: MdocDocument[];
  status: number;
}

/**
 * Parse a CBOR-encoded DeviceResponse into typed structures.
 *
 * @param data - Raw CBOR bytes of the DeviceResponse
 * @returns Parsed DeviceResponse with typed documents
 * @throws If the structure is malformed
 */
export function parseDeviceResponse(data: Uint8Array): DeviceResponse {
  const decoded = decodeMdoc<Map<string, unknown> | Record<string, unknown>>(data);

  const version = mapGetRequired<string>(decoded, 'version', 'DeviceResponse');
  const status = mapGetRequired<number>(decoded, 'status', 'DeviceResponse');
  const documentsRaw = mapGetRequired<unknown[]>(decoded, 'documents', 'DeviceResponse');

  if (!Array.isArray(documentsRaw)) {
    throw new Error('DeviceResponse.documents must be an array');
  }

  const documents = documentsRaw.map((doc, i) => parseDocument(doc, i));

  return { version, documents, status };
}

/**
 * Parse a single Document from a DeviceResponse.
 */
function parseDocument(raw: unknown, index: number): MdocDocument {
  if (!raw || typeof raw !== 'object') {
    throw new Error(`Document[${index}] is not an object`);
  }

  const doc = raw as Map<string, unknown> | Record<string, unknown>;
  const docType = mapGetRequired<string>(doc, 'docType', `Document[${index}]`);
  const issuerSignedRaw = mapGetRequired<unknown>(doc, 'issuerSigned', `Document[${index}]`);
  const deviceSignedRaw = mapGetOptional<unknown>(doc, 'deviceSigned');

  const issuerSigned = parseIssuerSigned(issuerSignedRaw, index);
  const deviceSigned = deviceSignedRaw ? parseDeviceSigned(deviceSignedRaw, index) : undefined;

  return { docType, issuerSigned, deviceSigned };
}

/**
 * Parse IssuerSigned structure.
 *
 * IssuerSigned = {
 *   nameSpaces: NameSpaces,     -- Map<namespace, [+ IssuerSignedItemBytes]>
 *   issuerAuth: COSE_Sign1      -- raw CBOR bytes
 * }
 *
 * IssuerSignedItemBytes = Tag 24 encoded IssuerSignedItem
 */
function parseIssuerSigned(raw: unknown, docIndex: number): IssuerSigned {
  if (!raw || typeof raw !== 'object') {
    throw new Error(`Document[${docIndex}].issuerSigned is not an object`);
  }

  const obj = raw as Map<string, unknown> | Record<string, unknown>;
  const issuerAuth = mapGetRequired<Uint8Array>(obj, 'issuerAuth', `IssuerSigned[${docIndex}]`);
  const nameSpacesRaw = mapGetRequired<unknown>(obj, 'nameSpaces', `IssuerSigned[${docIndex}]`);

  if (!(issuerAuth instanceof Uint8Array)) {
    throw new Error(`IssuerSigned[${docIndex}].issuerAuth must be a byte string`);
  }

  const nameSpaces = parseNameSpaces(nameSpacesRaw, docIndex);

  return { nameSpaces, issuerAuth };
}

/**
 * Parse NameSpaces — Map<namespace, IssuerSignedItem[]>.
 *
 * Each item in the array is either already decoded (via Tag 24 auto-decode)
 * or is raw bytes that need CBOR decoding.
 */
function parseNameSpaces(
  raw: unknown,
  docIndex: number
): Map<NameSpace, IssuerSignedItem[]> {
  const result = new Map<NameSpace, IssuerSignedItem[]>();

  if (raw instanceof Map) {
    for (const [ns, items] of raw) {
      if (!Array.isArray(items)) {
        throw new Error(`NameSpaces["${ns}"] in Document[${docIndex}] must be an array`);
      }
      result.set(ns as string, items.map((item, i) => parseIssuerSignedItem(item, ns as string, i)));
    }
  } else if (raw && typeof raw === 'object') {
    for (const [ns, items] of Object.entries(raw as Record<string, unknown>)) {
      if (!Array.isArray(items)) {
        throw new Error(`NameSpaces["${ns}"] in Document[${docIndex}] must be an array`);
      }
      result.set(ns, items.map((item, i) => parseIssuerSignedItem(item, ns, i)));
    }
  } else {
    throw new Error(`NameSpaces in Document[${docIndex}] is not a map/object`);
  }

  return result;
}

/**
 * Parse a single IssuerSignedItem.
 * May already be decoded (object/Map) or may need CBOR decoding (Uint8Array).
 */
function parseIssuerSignedItem(
  raw: unknown,
  namespace: string,
  index: number
): IssuerSignedItem {
  let item: Record<string, unknown> | Map<string, unknown>;

  if (raw instanceof Uint8Array) {
    item = decodeMdoc<Record<string, unknown> | Map<string, unknown>>(raw);
  } else if (raw && typeof raw === 'object') {
    item = raw as Record<string, unknown> | Map<string, unknown>;
  } else {
    throw new Error(`IssuerSignedItem[${index}] in "${namespace}" is not valid`);
  }

  const digestID = mapGetRequired<number>(item, 'digestID', `Item[${namespace}][${index}]`);
  const random = mapGetRequired<Uint8Array>(item, 'random', `Item[${namespace}][${index}]`);
  const elementIdentifier = mapGetRequired<string>(
    item, 'elementIdentifier', `Item[${namespace}][${index}]`
  );
  const elementValue = mapGetOptional<DataElementValue>(item, 'elementValue');

  return { digestID, random, elementIdentifier, elementValue };
}

/**
 * Parse DeviceSigned structure.
 *
 * DeviceSigned = {
 *   nameSpaces: DeviceNameSpaces,  -- usually empty
 *   deviceAuth: DeviceAuth
 * }
 */
function parseDeviceSigned(raw: unknown, docIndex: number): DeviceSigned {
  if (!raw || typeof raw !== 'object') {
    throw new Error(`Document[${docIndex}].deviceSigned is not an object`);
  }

  const obj = raw as Map<string, unknown> | Record<string, unknown>;
  const deviceAuthRaw = mapGetRequired<unknown>(obj, 'deviceAuth', `DeviceSigned[${docIndex}]`);
  const nameSpacesRaw = mapGetOptional<unknown>(obj, 'nameSpaces') ?? new Map();

  const deviceAuth = parseDeviceAuth(deviceAuthRaw, docIndex);
  const nameSpaces = nameSpacesRaw instanceof Map
    ? nameSpacesRaw as Map<NameSpace, DataElementValue>
    : new Map(Object.entries(nameSpacesRaw as Record<string, unknown>));

  return { nameSpaces, deviceAuth };
}

/**
 * Parse DeviceAuth structure.
 */
function parseDeviceAuth(raw: unknown, docIndex: number): DeviceAuth {
  if (!raw || typeof raw !== 'object') {
    throw new Error(`DeviceAuth in Document[${docIndex}] is not an object`);
  }

  const obj = raw as Map<string, unknown> | Record<string, unknown>;
  const deviceSignature = mapGetOptional<Uint8Array>(obj, 'deviceSignature');
  const deviceMac = mapGetOptional<Uint8Array>(obj, 'deviceMac');

  if (!deviceSignature && !deviceMac) {
    throw new Error(`DeviceAuth in Document[${docIndex}] has no deviceSignature or deviceMac`);
  }

  return {
    ...(deviceSignature ? { deviceSignature } : {}),
    ...(deviceMac ? { deviceMac } : {}),
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function mapGetRequired<T>(
  obj: Map<string, unknown> | Record<string, unknown>,
  key: string,
  context: string
): T {
  const value = mapGet(obj, key);
  if (value === undefined) {
    throw new Error(`${context} missing required field "${key}"`);
  }
  return value as T;
}

function mapGetOptional<T>(
  obj: Map<string, unknown> | Record<string, unknown>,
  key: string
): T | undefined {
  return mapGet(obj, key) as T | undefined;
}
