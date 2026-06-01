import { describe, expect, it } from 'vitest';
import { createDecisionCapsule } from '../src/decisionCapsule';
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
      claim: 'dateOfBirth',
      operation: 'ageAtLeast',
      value: 18,
      responseMode: 'PREDICATE_PROOF',
    },
  ],
  deniedClaims: [
    {
      claim: 'dateOfBirth',
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
  requestedClaims: ['dateOfBirth'],
  requestedPredicates: [{ claim: 'dateOfBirth', operation: 'ageAtLeast', value: 18 }],
  nonce: 'test_nonce_not_secret',
  audience: 'did:web:shop.trusted-age-verifier.example',
  timestamp: '2026-05-08T00:00:00.000Z',
};

describe('decision capsule policy evidence', () => {
  it('creates a golden PII-safe decision capsule for age verification', () => {
    const decision = evaluateDisclosureRequest(requestFixture, policyFixture);
    const capsule = createDecisionCapsule({
      decision,
      policy: policyFixture,
      request: requestFixture,
      timestamp: '2026-05-08T00:00:00.000Z',
    });

    expect(capsule.verdict).toBe('PROMPT');
    expect(capsule.responseMode).toBe('PREDICATE_PROOF');
    expect(capsule.deniedClaims).toContain('dateOfBirth');
    expect(capsule.allowedDisclosureType).toBe('predicate');
    expect(capsule.allowedPredicateId).toBe('predicate.age.gte.18');
    expect(capsule.rawClaimsStored).toBe(false);
    expect(capsule.proofMaterialStored).toBe(false);
    expect(capsule.reasonCodes).toEqual(
      expect.arrayContaining([
        REASON_CODES.RAW_ATTRIBUTE_NOT_PROPORTIONAL,
        REASON_CODES.MINIMAL_DISCLOSURE_REQUIRED,
      ])
    );

    const capsuleJson = JSON.stringify(capsule);
    expect(capsuleJson).not.toContain(requestFixture.verifierDid);
    expect(capsuleJson).not.toContain(requestFixture.nonce as string);
    expect(capsuleJson).not.toContain('1990-01-01');

    expect(capsule.verifierRef).toBeTruthy();
    expect(capsule.verifierRef).not.toBe(requestFixture.verifierDid);
    expect(capsule.inputHash).toBeTruthy();
    expect(capsule.policyHash).toBeTruthy();
  });

  it('is deterministic for same decision, policy, request, and timestamp', () => {
    const decision = evaluateDisclosureRequest(requestFixture, policyFixture);
    const input = {
      decision,
      policy: policyFixture,
      request: requestFixture,
      timestamp: '2026-05-08T00:00:00.000Z',
    };

    expect(createDecisionCapsule(input)).toEqual(createDecisionCapsule(input));
  });

  it('changes capsuleId across timestamps while keeping stable policyHash and inputHash', () => {
    const decision = evaluateDisclosureRequest(requestFixture, policyFixture);
    const baseInput = { decision, policy: policyFixture, request: requestFixture };

    const earlierCapsule = createDecisionCapsule({ ...baseInput, timestamp: '2026-05-08T00:00:00.000Z' });
    const laterCapsule = createDecisionCapsule({ ...baseInput, timestamp: '2026-05-08T00:10:00.000Z' });

    expect(earlierCapsule.capsuleId).not.toBe(laterCapsule.capsuleId);
    expect(earlierCapsule.policyHash).toBe(laterCapsule.policyHash);
    expect(earlierCapsule.inputHash).toBe(laterCapsule.inputHash);
  });

  it('creates a deny capsule when nonce is missing', () => {
    const { nonce: _nonce, ...requestWithoutNonce } = requestFixture;
    const decision = evaluateDisclosureRequest(requestWithoutNonce, policyFixture);
    const capsule = createDecisionCapsule({
      decision,
      policy: policyFixture,
      request: requestWithoutNonce,
      timestamp: '2026-05-08T00:00:00.000Z',
    });

    expect(capsule.verdict).toBe('DENY');
    expect(capsule.responseMode).toBe('NONE');
    expect(capsule.reasonCodes).toEqual(expect.arrayContaining([REASON_CODES.NONCE_REQUIRED, REASON_CODES.FAIL_CLOSED]));
    expect(capsule.rawClaimsStored).toBe(false);
    expect(capsule.proofMaterialStored).toBe(false);
  });
});
