/**
 * @module @mitch/mdoc/verifier
 *
 * ISO 18013-5 §8 — Full Offline mdoc Verification Pipeline.
 *
 * Orchestrates all verification steps for an mdoc presentation:
 * 1. Issuer authentication (COSE_Sign1 signature on MSO)
 * 2. MSO digest verification (disclosed items match MSO digests)
 * 3. MSO validity check (date range)
 * 4. DocType consistency (MSO docType == document docType)
 * 5. Device authentication (holder key signature over session transcript)
 *
 * Fail-closed: any step fails → entire verification fails.
 */

import type {
  MdocDocument,
  MobileSecurityObject,
  SessionTranscript,
  IssuerSignedItem,
  NameSpace,
} from './mdoc-types.js';
import { extractAndVerifyMso } from './mso.js';
import { verifyMsoValidity, verifyDocType } from './validity.js';
import { verifyDeviceAuth } from './device-auth.js';
import { decodeCoseSign1 } from './cose.js';
import {
  extractX5Chain,
  importPublicKeyFromCert,
  type TrustAnchorVerifier,
} from './x5chain.js';

/** Per-step verification status. */
export interface VerificationStep {
  step: string;
  valid: boolean;
  reason?: string;
}

/** Full offline verification result. */
export interface MdocVerificationResult {
  /** Overall result — true only if ALL steps pass. */
  valid: boolean;
  /** Per-step results for diagnostics. */
  steps: VerificationStep[];
  /** Extracted MSO (available even on partial failure for diagnostics). */
  mso?: MobileSecurityObject;
  /** Summary reason on failure. */
  reason?: string;
}

/** Options for mdoc offline verification. */
export interface MdocVerifyOptions {
  /** The mdoc document to verify. */
  document: MdocDocument;
  /** Session transcript for device authentication binding. */
  sessionTranscript: SessionTranscript;
  /**
   * Issuer public key for MSO signature verification.
   * If not provided, the verifier will attempt to extract it from x5chain
   * in the COSE_Sign1 headers.
   */
  issuerPublicKey?: CryptoKey;
  /**
   * Trust anchor verifier callback for x5chain validation.
   * Called with the certificate chain (DER bytes, leaf first).
   * Return true if the chain is trusted.
   * If not provided and no issuerPublicKey given, x5chain extraction
   * is used but trust is not verified (suitable for testing).
   */
  trustAnchorVerifier?: TrustAnchorVerifier;
  /** Current time for validity checks (defaults to now). */
  now?: Date;
  /**
   * Reader's ECDH private key (required for COSE_Mac0 device authentication).
   * Used for ECDH key agreement with the device to derive the MAC key.
   */
  eReaderPrivateKey?: CryptoKey;
}

/**
 * Full ISO 18013-5 §8 offline verification of an mdoc document.
 *
 * Steps executed in order (fail-closed — stops on first critical failure):
 * 1. **Issuer Auth**: Verify COSE_Sign1 signature on the MSO
 * 2. **MSO Digests**: Verify disclosed item digests match MSO
 * 3. **Validity**: Check MSO validityInfo date range
 * 4. **DocType**: Check MSO docType matches document docType
 * 5. **Device Auth**: Verify device signature (if deviceSigned present)
 *
 * @returns Detailed result with per-step status
 */
export async function verifyMdocOffline(
  opts: MdocVerifyOptions
): Promise<MdocVerificationResult> {
  const { document, sessionTranscript, now } = opts;
  const steps: VerificationStep[] = [];

  // ── Step 0: Resolve issuer public key ──────────────────────────────────
  let issuerPublicKey = opts.issuerPublicKey;

  if (!issuerPublicKey) {
    try {
      const parsed = decodeCoseSign1(document.issuerSigned.issuerAuth);
      const x5result = extractX5Chain(parsed.decodedProtectedHeaders, parsed.unprotectedHeaders);

      if (opts.trustAnchorVerifier) {
        const trusted = await opts.trustAnchorVerifier(x5result.chain);
        if (!trusted) {
          steps.push({ step: 'trust-anchor', valid: false, reason: 'Certificate chain not trusted' });
          return { valid: false, steps, reason: 'Certificate chain not trusted' };
        }
        steps.push({ step: 'trust-anchor', valid: true });
      }

      issuerPublicKey = await importPublicKeyFromCert(x5result.leaf);
    } catch (err) {
      const reason = `Issuer key resolution failed: ${err instanceof Error ? err.message : String(err)}`;
      steps.push({ step: 'issuer-key-resolution', valid: false, reason });
      return { valid: false, steps, reason };
    }
  }

  // ── Step 1: Issuer Auth (COSE_Sign1 signature + MSO digest verification) ──
  const msoResult = await extractAndVerifyMso(
    document.issuerSigned.issuerAuth,
    document.issuerSigned.nameSpaces,
    issuerPublicKey
  );

  steps.push({
    step: 'issuer-auth',
    valid: msoResult.valid,
    reason: msoResult.reason,
  });

  if (!msoResult.valid || !msoResult.mso) {
    return {
      valid: false,
      steps,
      mso: msoResult.mso,
      reason: msoResult.reason ?? 'Issuer authentication failed',
    };
  }

  const mso = msoResult.mso;

  // ── Step 2: Validity ───────────────────────────────────────────────────
  const validityResult = verifyMsoValidity(mso.validityInfo, now);
  steps.push({
    step: 'validity',
    valid: validityResult.valid,
    reason: validityResult.reason,
  });

  if (!validityResult.valid) {
    return {
      valid: false,
      steps,
      mso,
      reason: validityResult.reason,
    };
  }

  // ── Step 3: DocType ────────────────────────────────────────────────────
  const docTypeResult = verifyDocType(mso.docType, document.docType);
  steps.push({
    step: 'doctype',
    valid: docTypeResult.valid,
    reason: docTypeResult.reason,
  });

  if (!docTypeResult.valid) {
    return {
      valid: false,
      steps,
      mso,
      reason: docTypeResult.reason,
    };
  }

  // ── Step 4: Device Auth ────────────────────────────────────────────────
  if (document.deviceSigned) {
    const deviceResult = await verifyDeviceAuth(
      document.deviceSigned.deviceAuth,
      mso,
      sessionTranscript,
      opts.eReaderPrivateKey,
    );
    steps.push({
      step: 'device-auth',
      valid: deviceResult.valid,
      reason: deviceResult.reason,
    });

    if (!deviceResult.valid) {
      return {
        valid: false,
        steps,
        mso,
        reason: deviceResult.reason,
      };
    }
  } else {
    // No device auth — fail-closed per ISO 18013-5
    steps.push({
      step: 'device-auth',
      valid: false,
      reason: 'No deviceSigned in document (device authentication required)',
    });
    return {
      valid: false,
      steps,
      mso,
      reason: 'No deviceSigned in document',
    };
  }

  // ── All steps passed ──────────────────────────────────────────────────
  return { valid: true, steps, mso };
}
