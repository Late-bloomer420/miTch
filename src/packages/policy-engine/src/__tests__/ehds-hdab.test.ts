/**
 * T-A3: HDAB Permit Check — requiresHdabPermit flow
 */
import { describe, it, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';

const HDAB_POLICY: PolicyManifest = {
  version: '1.2',
  owner: 'did:example:wallet-user',
  globalSettings: { blockUnknownVerifiers: true, defaultDeny: true },
  trustedIssuers: [
    { did: 'did:eu:research-institute-*', name: 'EU Research', credentialTypes: ['PatientSummary'], issuerRole: 'hdab' as const },
    { did: 'did:example:ehealth-authority', name: 'eHealth', credentialTypes: ['PatientSummary'] },
  ],
  rules: [
    { id: 'rule-research', verifierPattern: 'did:eu:research-*', allowedClaims: ['bloodGroup'], requiresHdabPermit: true, requiresUserConsent: true, usagePurpose: 'researchSecondary' as const, priority: 50 },
    { id: 'rule-hospital', verifierPattern: 'hospital-*', allowedClaims: ['bloodGroup'], requiresUserConsent: true, priority: 60 },
  ],
};

const CREDENTIAL: StoredCredentialMetadata = {
  id: 'vc-health-001',
  issuer: 'did:example:ehealth-authority',
  type: ['VerifiableCredential', 'PatientSummary'],
  issuedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
  expiresAt: new Date(Date.now() + 350 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['bloodGroup', 'allergies'],
  provenClaims: [],
};

const ctx: EvaluationContext = { timestamp: Date.now(), userDID: 'did:example:wallet-user' };

describe('EHDS HDAB Permit Check', () => {
  const engine = new PolicyEngine();

  it('research verifier WITH matching HDAB issuer → PROMPT', async () => {
    const request: VerifierRequest = {
      verifierId: 'did:eu:research-institute-alpha',
      origin: 'https://research.example.eu',
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup'],
        requestedProvenClaims: [],
      }],
    };
    const result = await engine.evaluate(request, ctx, [CREDENTIAL], HDAB_POLICY);
    expect(result.verdict).toBe('PROMPT');
    expect(result.reasonCodes).not.toContain(ReasonCode.HDAB_PERMIT_REQUIRED);
  });

  it('research verifier WITHOUT HDAB issuer → DENY + HDAB_PERMIT_REQUIRED', async () => {
    const policyNoHdab: PolicyManifest = {
      ...HDAB_POLICY,
      trustedIssuers: [
        { did: 'did:example:ehealth-authority', name: 'eHealth', credentialTypes: ['PatientSummary'] },
      ],
    };
    const request: VerifierRequest = {
      verifierId: 'did:eu:research-institute-alpha',
      origin: 'https://research.example.eu',
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup'],
        requestedProvenClaims: [],
      }],
    };
    const result = await engine.evaluate(request, ctx, [CREDENTIAL], policyNoHdab);
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(ReasonCode.HDAB_PERMIT_REQUIRED);
  });

  it('hospital verifier (no requiresHdabPermit) → PROMPT regardless of HDAB', async () => {
    const request: VerifierRequest = {
      verifierId: 'hospital-vienna-01',
      origin: 'https://hospital.example.at',
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup'],
        requestedProvenClaims: [],
      }],
    };
    const result = await engine.evaluate(request, ctx, [CREDENTIAL], HDAB_POLICY);
    expect(result.verdict).toBe('PROMPT');
    expect(result.reasonCodes).not.toContain(ReasonCode.HDAB_PERMIT_REQUIRED);
  });
});
