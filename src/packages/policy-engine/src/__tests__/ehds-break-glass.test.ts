/**
 * T-B1: Break-Glass Emergency Access
 * EHDS Art. 8(5) — grant access when user is unconscious/unreachable
 */
import { describe, it, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';

const POLICY: PolicyManifest = {
  version: '1.0',
  trustedIssuers: [
    { did: 'did:example:ehealth-authority', name: 'eHealth', credentialTypes: ['PatientSummary', 'VerifiableCredential'] },
  ],
  rules: [
    {
      id: 'rule-er-breakglass',
      verifierPattern: 'hospital-*-er-*',
      allowedClaims: ['bloodGroup', 'allergies', 'emergencyContacts'],
      provenClaims: [],
      deniedClaims: ['geneticData'],
      requiresUserConsent: true,
      requiresPresence: true,
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 730,
      priority: 100,
      allowBreakGlass: true,
    },
    {
      id: 'rule-er-no-breakglass',
      verifierPattern: 'clinic-*',
      allowedClaims: ['bloodGroup', 'allergies'],
      provenClaims: [],
      deniedClaims: [],
      requiresUserConsent: true,
      requiresPresence: true,
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 730,
      priority: 50,
      // allowBreakGlass intentionally omitted
    },
    {
      id: 'rule-pharmacy',
      verifierPattern: 'pharmacy-*',
      allowedClaims: ['medication'],
      provenClaims: [],
      deniedClaims: [],
      requiresUserConsent: true,
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 30,
      priority: 40,
    },
  ],
};

const CREDENTIAL: StoredCredentialMetadata = {
  id: 'vc-health-001',
  issuer: 'did:example:ehealth-authority',
  type: ['VerifiableCredential', 'PatientSummary'],
  issuedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['bloodGroup', 'allergies', 'emergencyContacts', 'medication'],
};

const ER_REQUEST: VerifierRequest = {
  verifierId: 'hospital-vienna-er-1',
  requirements: [{
    credentialType: 'PatientSummary',
    requestedClaims: ['bloodGroup', 'allergies'],
    requestedProvenClaims: [],
  }],
};

describe('T-B1: Break-Glass Emergency Access', () => {
  const engine = new PolicyEngine();

  it('ER + userPresent:false + allowBreakGlass → ALLOW + BREAK_GLASS_ACTIVATED', async () => {
    const ctx: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:patient',
      interaction: { timestamp: Date.now(), userAgent: 'ER-terminal', userPresent: false },
    };

    const result = await engine.evaluate(ER_REQUEST, ctx, [CREDENTIAL], POLICY);
    expect(result.verdict).toBe('ALLOW');
    expect(result.reasonCodes).toContain(ReasonCode.BREAK_GLASS_ACTIVATED);
  });

  it('ER + userPresent:true + allowBreakGlass → PROMPT (normal consent flow)', async () => {
    const ctx: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:patient',
      interaction: { timestamp: Date.now(), userAgent: 'ER-terminal', userPresent: true },
    };

    const result = await engine.evaluate(ER_REQUEST, ctx, [CREDENTIAL], POLICY);
    expect(result.verdict).toBe('PROMPT');
    expect(result.reasonCodes).not.toContain(ReasonCode.BREAK_GLASS_ACTIVATED);
    expect(result.reasonCodes).toContain(ReasonCode.CONSENT_REQUIRED);
  });

  it('ER + userPresent:false + no allowBreakGlass → PROMPT (no break-glass bypass)', async () => {
    const ctx: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:patient',
      interaction: { timestamp: Date.now(), userAgent: 'clinic-terminal', userPresent: false },
    };

    const request: VerifierRequest = {
      verifierId: 'clinic-downtown',
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup', 'allergies'],
        requestedProvenClaims: [],
      }],
    };

    const result = await engine.evaluate(request, ctx, [CREDENTIAL], POLICY);
    expect(result.verdict).toBe('PROMPT');
    expect(result.reasonCodes).not.toContain(ReasonCode.BREAK_GLASS_ACTIVATED);
  });

  it('Non-ER + userPresent:false → normal rules, no break-glass', async () => {
    const ctx: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:patient',
      interaction: { timestamp: Date.now(), userAgent: 'pharmacy-app', userPresent: false },
    };

    const request: VerifierRequest = {
      verifierId: 'pharmacy-central',
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['medication'],
        requestedProvenClaims: [],
      }],
    };

    const result = await engine.evaluate(request, ctx, [CREDENTIAL], POLICY);
    // pharmacy rule has requiresUserConsent but no allowBreakGlass
    expect(result.verdict).toBe('PROMPT');
    expect(result.reasonCodes).not.toContain(ReasonCode.BREAK_GLASS_ACTIVATED);
  });
});
