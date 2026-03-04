import { describe, it, expect } from 'vitest';
import { mapWebAuthnReason } from '../webauthn-reason-map';
import { DenyReasonCode } from '../deny-reason-codes';

describe('mapWebAuthnReason', () => {
  it('maps CHALLENGE_EXPIRED → PRESENCE_REQUIRED (user didn\'t tap in time)', () => {
    expect(mapWebAuthnReason('CHALLENGE_EXPIRED')).toBe(DenyReasonCode.PRESENCE_REQUIRED);
  });

  it('maps CHALLENGE_NOT_FOUND → REAUTH_REQUIRED (session lost, need full re-auth)', () => {
    expect(mapWebAuthnReason('CHALLENGE_NOT_FOUND')).toBe(DenyReasonCode.REAUTH_REQUIRED);
  });

  it('maps CHALLENGE_MISMATCH → BINDING_FAILED', () => {
    expect(mapWebAuthnReason('CHALLENGE_MISMATCH')).toBe(DenyReasonCode.BINDING_FAILED);
  });

  it('maps COUNTER_REPLAY → BINDING_FAILED', () => {
    expect(mapWebAuthnReason('COUNTER_REPLAY')).toBe(DenyReasonCode.BINDING_FAILED);
  });

  it('maps SIGNATURE_INVALID → CRYPTO_VERIFY_FAILED', () => {
    expect(mapWebAuthnReason('SIGNATURE_INVALID')).toBe(DenyReasonCode.CRYPTO_VERIFY_FAILED);
  });

  it('maps KEY_NOT_FOUND → NO_SUITABLE_CREDENTIAL', () => {
    expect(mapWebAuthnReason('KEY_NOT_FOUND')).toBe(DenyReasonCode.NO_SUITABLE_CREDENTIAL);
  });

  it('maps unknown reason → INTERNAL_SAFE_FAILURE (fail-closed)', () => {
    expect(mapWebAuthnReason('SOMETHING_UNKNOWN')).toBe(DenyReasonCode.INTERNAL_SAFE_FAILURE);
    expect(mapWebAuthnReason('')).toBe(DenyReasonCode.INTERNAL_SAFE_FAILURE);
  });

  it('is deterministic — same input always produces same output', () => {
    const reasons = [
      'CHALLENGE_EXPIRED', 'CHALLENGE_NOT_FOUND', 'CHALLENGE_MISMATCH',
      'COUNTER_REPLAY', 'SIGNATURE_INVALID', 'KEY_NOT_FOUND', 'UNKNOWN',
    ];
    for (const reason of reasons) {
      expect(mapWebAuthnReason(reason)).toBe(mapWebAuthnReason(reason));
    }
  });
});
