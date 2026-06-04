/**
 * OID4VP Verifier — mdoc (ISO 18013-5) presentation verification.
 *
 * Bridges the OID4VP authorization response flow with the @askmi/mdoc
 * offline verification pipeline. Handles:
 * - Base64-encoded DeviceResponse parsing
 * - Full offline verification (issuer-auth, digests, validity, doctype, device-auth)
 * - Disclosed claim extraction from verified namespaces
 */

import {
  parseDeviceResponse,
  verifyMdocOffline,
  type MdocVerificationResult,
  type MdocVerifyOptions,
  type SessionTranscript,
  type MdocDocument,
  type IssuerSignedItem,
  type TrustAnchorVerifier,
} from '@askmi/mdoc';

// ─── Types ───────────────────────────────────────────────────────────

export interface MdocPresentationOptions {
  /** Base64url-encoded DeviceResponse CBOR bytes. */
  deviceResponseBase64: string;
  /** Session transcript for device authentication binding. */
  sessionTranscript: SessionTranscript;
  /** Issuer public key (if known; otherwise x5chain extraction is used). */
  issuerPublicKey?: CryptoKey;
  /** Trust anchor verifier for x5chain validation. */
  trustAnchorVerifier?: TrustAnchorVerifier;
  /** Current time override (for testing). */
  now?: Date;
}

export interface MdocPresentationResult {
  /** Overall verification result. */
  valid: boolean;
  /** Disclosed claims (namespace-flattened). */
  disclosedClaims: Record<string, unknown>;
  /** Per-document results. */
  documents: MdocDocumentResult[];
  /** Error messages (empty on success). */
  errors: string[];
}

export interface MdocDocumentResult {
  docType: string;
  verification: MdocVerificationResult;
  /** Disclosed claims for this document, keyed by namespace. */
  namespaceClaims: Record<string, Record<string, unknown>>;
}

// ─── Helpers ─────────────────────────────────────────────────────────

function base64urlToBytes(base64url: string): Uint8Array {
  // Normalize base64url → base64
  let b64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Extract disclosed claims from an MdocDocument's issuerSigned nameSpaces.
 * Returns claims grouped by namespace and a flat merged map.
 */
function extractDisclosedClaims(doc: MdocDocument): {
  namespaceClaims: Record<string, Record<string, unknown>>;
  flat: Record<string, unknown>;
} {
  const namespaceClaims: Record<string, Record<string, unknown>> = {};
  const flat: Record<string, unknown> = {};

  for (const [ns, items] of doc.issuerSigned.nameSpaces) {
    const nsClaims: Record<string, unknown> = {};
    for (const item of items as IssuerSignedItem[]) {
      const id = item.elementIdentifier;
      const value = item.elementValue;
      nsClaims[id] = value;
      flat[id] = value;
    }
    namespaceClaims[ns] = nsClaims;
  }

  return { namespaceClaims, flat };
}

// ─── Main Verification ───────────────────────────────────────────────

/**
 * Verify an mdoc presentation from an OID4VP authorization response.
 *
 * Pipeline:
 * 1. Decode base64url DeviceResponse → CBOR → typed documents
 * 2. For each document: run verifyMdocOffline (5-step fail-closed)
 * 3. Extract disclosed claims from verified documents only
 *
 * Fail-closed: if any document fails verification, its claims are excluded.
 */
export async function verifyMdocPresentation(
  opts: MdocPresentationOptions
): Promise<MdocPresentationResult> {
  const errors: string[] = [];
  const documents: MdocDocumentResult[] = [];
  const allDisclosedClaims: Record<string, unknown> = {};

  // 1. Decode DeviceResponse
  let deviceResponseBytes: Uint8Array;
  try {
    deviceResponseBytes = base64urlToBytes(opts.deviceResponseBase64);
  } catch (err) {
    return {
      valid: false,
      disclosedClaims: {},
      documents: [],
      errors: [`Failed to decode DeviceResponse base64: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  let parsedDocs: MdocDocument[];
  try {
    const deviceResponse = parseDeviceResponse(deviceResponseBytes);
    parsedDocs = deviceResponse.documents;
  } catch (err) {
    return {
      valid: false,
      disclosedClaims: {},
      documents: [],
      errors: [`Failed to parse DeviceResponse CBOR: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (parsedDocs.length === 0) {
    return {
      valid: false,
      disclosedClaims: {},
      documents: [],
      errors: ['DeviceResponse contains no documents'],
    };
  }

  // 2. Verify each document
  let allValid = true;
  for (const doc of parsedDocs) {
    const verifyOpts: MdocVerifyOptions = {
      document: doc,
      sessionTranscript: opts.sessionTranscript,
      issuerPublicKey: opts.issuerPublicKey,
      trustAnchorVerifier: opts.trustAnchorVerifier,
      now: opts.now,
    };

    let verification: MdocVerificationResult;
    try {
      verification = await verifyMdocOffline(verifyOpts);
    } catch (err) {
      verification = {
        valid: false,
        steps: [],
        reason: `Verification threw: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const { namespaceClaims, flat } = extractDisclosedClaims(doc);

    if (verification.valid) {
      // Only merge claims from verified documents
      Object.assign(allDisclosedClaims, flat);
    } else {
      allValid = false;
      errors.push(
        `Document ${doc.docType} failed verification: ${verification.reason ?? 'unknown'}`
      );
    }

    documents.push({
      docType: doc.docType,
      verification,
      namespaceClaims,
    });
  }

  return {
    valid: allValid,
    disclosedClaims: allDisclosedClaims,
    documents,
    errors,
  };
}
