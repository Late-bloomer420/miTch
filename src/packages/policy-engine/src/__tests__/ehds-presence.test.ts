/**
 * Integration Test: EHDS Emergency Room — requiresPresence flow
 * Verifies that hospital-*-er-* triggers PROMPT + PRESENCE_REQUIRED
 */
import { describe, it, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';

const EHDS_POLICY: PolicyManifest = {
  version: '1.2',
  owner: 'did:example:wallet-user',
  globalSettings: {
    blockUnknownVerifiers: true,
    defaultDeny: true,
  },
  trustedIssuers: [
    { did: 'did:example:ehealth-authority', credentialTypes: ['PatientSummary', 'VerifiableCredential'] },
    { did: 'did:example:gov-issuer', credentialTypes: ['AgeCredential', 'VerifiableCredential'] },
  ],
  rules: [
    {
      id: 'rule-ehds-emergency-01',
      verifierPattern: 'hospital-*-er-*',
      context: 'EHDS Emergency Room',
      allowedClaims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
      provenClaims: [],
      deniedClaims: ['insuranceId', 'financialData', 'geneticData'],
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 365,
      requiresUserConsent: true,
      requiresPresence: true,
      priority: 95,
    },
    {
      id: 'rule-liquor-store',
      verifierPattern: 'did:mitch:verifier-liquor-store',
      allowedClaims: [],
      provenClaims: ['age >= 18'],
      deniedClaims: ['birthDate'],
      requiresUserConsent: false,
      priority: 50,
    },
  ],
};

const EHDS_CREDENTIAL: StoredCredentialMetadata = {
  id: 'vc-ehds-health-001',
  issuer: 'did:example:ehealth-authority',
  type: ['VerifiableCredential', 'PatientSummary'],
  issuedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
};

const AGE_CREDENTIAL: StoredCredentialMetadata = {
  id: 'vc-age-789',
  issuer: 'did:example:gov-issuer',
  type: ['VerifiableCredential', 'AgeCredential'],
  issuedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['birthDate', 'age'],
};

describe('EHDS Emergency: requiresPresence flow', () => {
  const engine = new PolicyEngine();
  const ctx: EvaluationContext = { timestamp: Date.now(), userDID: 'did:example:wallet-user' };

  it('hospital ER request → PROMPT + PRESENCE_REQUIRED + CONSENT_REQUIRED', async () => {
    const request: VerifierRequest = {
      verifierId: 'hospital-madrid-er-1',
      origin: 'https://er.hospital-madrid.es',
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup', 'allergies'],
        requestedProvenClaims: [],
      }],
    };

    const result = await engine.evaluate(request, ctx, [EHDS_CREDENTIAL], EHDS_POLICY);
    expect(result.verdict).toBe('PROMPT');
    expect(result.reasonCodes).toContain(ReasonCode.CONSENT_REQUIRED);
    expect(result.reasonCodes).toContain(ReasonCode.PRESENCE_REQUIRED);
    expect(result.decisionCapsule?.requires_presence).toBe(true);
  });

  it('liquor store request → ALLOW (no presence, no consent)', async () => {
    const request: VerifierRequest = {
      verifierId: 'did:mitch:verifier-liquor-store',
      origin: 'https://liquor.example.com',
      requirements: [{
        credentialType: 'AgeCredential',
        requestedClaims: [],
        requestedProvenClaims: ['age >= 18'],
      }],
    };

    const result = await engine.evaluate(request, ctx, [AGE_CREDENTIAL], EHDS_POLICY);
    expect(result.verdict).toBe('ALLOW');
    expect(result.reasonCodes).not.toContain(ReasonCode.PRESENCE_REQUIRED);
    expect(result.decisionCapsule?.requires_presence).toBe(false);
  });
});
