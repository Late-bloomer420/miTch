import { describe, expect, it } from 'vitest';
import { evaluateDisclosureRequest } from '../src/evaluateDisclosureRequest';
import { REASON_CODES } from '../src/reasonCodes';
import type { DisclosureRequest, Policy } from '../src/types';

const policyFixture: Policy = {
  id: 'policy.age_over_18.v1',
  version: '1.0.0',
  scope: {
    verifierPattern: 'did:web:*.trusted-age-verifier.example',
    purpose: 'age_verification',
  },
  defaults: {
    blockUnknownVerifiers: true,
    requiresTrustedIssuer: true,
    requiresUserConsent: true,
    requiresPresence: true,
    failClosed: true,
  },
  allowedClaims: [],
  allowedPredicates: [
    {
      id: 'predicate.age.gte.18',
      claim: 'birthdate',
      operation: 'ageAtLeast',
      value: 18,
      responseMode: 'PREDICATE_PROOF',
    },
  ],
  deniedClaims: [
    {
      claim: 'birthdate',
      reason: REASON_CODES.RAW_ATTRIBUTE_NOT_PROPORTIONAL,
    },
  ],
  linkabilityControls: {
    pairwiseDidRequired: true,
    audienceBindingRequired: true,
    nonceRequired: true,
    denyReusableProofs: true,
  },
};

const requestFixture: DisclosureRequest = {
  requestId: 'req_age_001',
  verifierDid: 'did:web:shop.trusted-age-verifier.example',
  purpose: 'age_verification',
  requestedClaims: ['birthdate'],
  requestedPredicates: [{ claim: 'birthdate', operation: 'ageAtLeast', value: 18 }],
  nonce: 'test_nonce_not_secret',
  audience: 'did:web:shop.trusted-age-verifier.example',
  timestamp: '2026-05-08T00:00:00.000Z',
};

describe('age verification disclosure policy', () => {
  it('denies raw birthdate but offers ageAtLeast(18) predicate proof for age_verification', () => {
    const decision = evaluateDisclosureRequest(requestFixture, policyFixture);

    expect(decision.verdict).toBe('PROMPT');
    expect(decision.responseMode).toBe('PREDICATE_PROOF');
    expect(decision.deniedClaims).toContain('birthdate');
    expect(decision.allowedDisclosure).toEqual({
      type: 'predicate',
      claim: 'birthdate',
      operation: 'ageAtLeast',
      value: 18,
    });
    expect(decision.reasonCodes).toEqual(
      expect.arrayContaining([
        REASON_CODES.PURPOSE_VALID,
        REASON_CODES.VERIFIER_PATTERN_MATCHED,
        REASON_CODES.RAW_ATTRIBUTE_NOT_PROPORTIONAL,
        REASON_CODES.MINIMAL_DISCLOSURE_REQUIRED,
        REASON_CODES.USER_CONSENT_REQUIRED,
        REASON_CODES.PRESENCE_REQUIRED,
      ])
    );
    expect(decision.rawClaimsDisclosed).toBe(false);
    expect(JSON.stringify(decision)).not.toContain('199');
  });

  it('fails closed when nonce is missing', () => {
    const { nonce: _nonce, ...requestWithoutNonce } = requestFixture;
    const decision = evaluateDisclosureRequest(requestWithoutNonce, policyFixture);
    expect(decision.verdict).toBe('DENY');
    expect(decision.responseMode).toBe('NONE');
    expect(decision.reasonCodes).toEqual(
      expect.arrayContaining([REASON_CODES.NONCE_REQUIRED, REASON_CODES.FAIL_CLOSED])
    );
  });

  it('fails closed on wrong purpose', () => {
    const decision = evaluateDisclosureRequest(
      { ...requestFixture, purpose: 'marketing' },
      policyFixture
    );
    expect(decision.verdict).toBe('DENY');
    expect(decision.responseMode).toBe('NONE');
    expect(decision.reasonCodes).toEqual(
      expect.arrayContaining([REASON_CODES.PURPOSE_MISMATCH, REASON_CODES.FAIL_CLOSED])
    );
  });

  it('fails closed for unknown verifier', () => {
    const decision = evaluateDisclosureRequest(
      { ...requestFixture, verifierDid: 'did:web:evil.example' },
      policyFixture
    );
    expect(decision.verdict).toBe('DENY');
    expect(decision.responseMode).toBe('NONE');
    expect(decision.reasonCodes).toEqual(
      expect.arrayContaining([REASON_CODES.VERIFIER_PATTERN_MISMATCH, REASON_CODES.FAIL_CLOSED])
    );
  });

  it('fails closed when no matching predicate exists', () => {
    const decision = evaluateDisclosureRequest(
      { ...requestFixture, requestedPredicates: [] },
      policyFixture
    );
    expect(decision.verdict).toBe('DENY');
    expect(decision.responseMode).toBe('NONE');
    expect(decision.reasonCodes).toEqual(
      expect.arrayContaining([REASON_CODES.NO_ALLOWED_DISCLOSURE_PATH, REASON_CODES.FAIL_CLOSED])
    );
  });
});
