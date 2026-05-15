/**
 * @module @mitch/mdoc/validity
 *
 * ISO 18013-5 §8.2.2.1 — MSO Validity and DocType verification.
 *
 * Fail-closed: expired, not-yet-valid, or mismatched docType → invalid.
 */

import type { MobileSecurityObject, ValidityInfo } from './mdoc-types.js';

/** Result of MSO validity verification. */
export interface ValidityResult {
  valid: boolean;
  reason?: string;
}

/**
 * Verify MSO validityInfo date range.
 *
 * Per ISO 18013-5 §9.1.2.4:
 * - validFrom must be <= now
 * - validUntil must be > now
 * - signed must be <= validFrom (logical ordering)
 *
 * Fail-closed: any date violation → invalid.
 *
 * @param validityInfo - The MSO validityInfo to check
 * @param now - Current time (injectable for testing, defaults to Date.now())
 */
export function verifyMsoValidity(
  validityInfo: ValidityInfo,
  now: Date = new Date()
): ValidityResult {
  const rawSigned = validityInfo.signed;
  const rawFrom = validityInfo.validFrom;
  const rawUntil = validityInfo.validUntil;

  // Coerce strings to Dates (CBOR decodes dates as strings)
  const signed = rawSigned instanceof Date ? rawSigned : new Date(rawSigned as unknown as string);
  const validFrom = rawFrom instanceof Date ? rawFrom : new Date(rawFrom as unknown as string);
  const validUntil = rawUntil instanceof Date ? rawUntil : new Date(rawUntil as unknown as string);

  if (isNaN(signed.getTime()) || isNaN(validFrom.getTime()) || isNaN(validUntil.getTime())) {
    return { valid: false, reason: 'ValidityInfo contains invalid dates' };
  }

  if (signed.getTime() > validFrom.getTime()) {
    return { valid: false, reason: 'MSO signed date is after validFrom' };
  }

  if (validFrom.getTime() > validUntil.getTime()) {
    return { valid: false, reason: 'MSO validFrom is after validUntil' };
  }

  if (now.getTime() < validFrom.getTime()) {
    return { valid: false, reason: 'MSO is not yet valid (validFrom is in the future)' };
  }

  if (now.getTime() >= validUntil.getTime()) {
    return { valid: false, reason: 'MSO has expired (validUntil is in the past)' };
  }

  return { valid: true };
}

/**
 * Verify that the MSO docType matches the expected document docType.
 *
 * Per ISO 18013-5 §8.2.2.1: the docType in the MSO must match
 * the docType in the MdocDocument.
 *
 * Fail-closed: mismatch → invalid.
 */
export function verifyDocType(
  msoDocType: string,
  documentDocType: string
): ValidityResult {
  if (!msoDocType || !documentDocType) {
    return { valid: false, reason: 'Missing docType' };
  }

  if (msoDocType !== documentDocType) {
    return {
      valid: false,
      reason: `DocType mismatch: MSO="${msoDocType}" vs document="${documentDocType}"`,
    };
  }

  return { valid: true };
}
