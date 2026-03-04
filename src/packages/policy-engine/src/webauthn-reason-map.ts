/**
 * @module @mitch/policy-engine/webauthn-reason-map
 *
 * Deterministic mapping from WebAuthn verification failure reasons
 * to policy-engine deny reason codes.
 *
 * Rationale:
 * - CHALLENGE_EXPIRED → PRESENCE_REQUIRED: User didn't interact with the
 *   authenticator within the challenge window (5 min). The session is still
 *   valid; they just need to tap/confirm again.
 * - CHALLENGE_NOT_FOUND → REAUTH_REQUIRED: No challenge exists for this user.
 *   The session was lost or already consumed. Full re-authentication needed.
 * - CHALLENGE_MISMATCH → BINDING_FAILED: Challenge value doesn't match
 *   (tampering or stale client state).
 * - COUNTER_REPLAY → BINDING_FAILED: Authenticator counter not incremented
 *   (cloned key / replay attack).
 * - SIGNATURE_INVALID → CRYPTO_VERIFY_FAILED: Signature or origin check failed.
 * - KEY_NOT_FOUND → NO_SUITABLE_CREDENTIAL: Authenticator not registered.
 */

import { DenyReasonCode } from './deny-reason-codes';

/** WebAuthn verification failure reasons (from @mitch/webauthn-verifier) */
export type WebAuthnFailureReason =
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_NOT_FOUND'
  | 'CHALLENGE_MISMATCH'
  | 'COUNTER_REPLAY'
  | 'SIGNATURE_INVALID'
  | 'KEY_NOT_FOUND';

/**
 * Map a WebAuthn failure reason to its corresponding deny reason code.
 *
 * This is deterministic and exhaustive — every WebAuthn reason maps to
 * exactly one deny code. Unknown reasons map to INTERNAL_SAFE_FAILURE
 * (fail-closed).
 */
export function mapWebAuthnReason(reason: string): DenyReasonCode {
  switch (reason) {
    case 'CHALLENGE_EXPIRED':
      return DenyReasonCode.PRESENCE_REQUIRED;
    case 'CHALLENGE_NOT_FOUND':
      return DenyReasonCode.REAUTH_REQUIRED;
    case 'CHALLENGE_MISMATCH':
      return DenyReasonCode.BINDING_FAILED;
    case 'COUNTER_REPLAY':
      return DenyReasonCode.BINDING_FAILED;
    case 'SIGNATURE_INVALID':
      return DenyReasonCode.CRYPTO_VERIFY_FAILED;
    case 'KEY_NOT_FOUND':
      return DenyReasonCode.NO_SUITABLE_CREDENTIAL;
    default:
      return DenyReasonCode.INTERNAL_SAFE_FAILURE;
  }
}
