/**
 * T-B2: ePrescription Single-Use Nullifier Tests
 *
 * Verifies that dispensed/revoked credentials are excluded from selection,
 * backward compatibility for undefined status, and correct deny reason codes.
 */

import { describe, it, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import type {
  PolicyManifest,
  VerifierRequest,
  StoredCredentialMetadata,
} from '@mitch/shared-types';

// --- Fixtures ---

const basePolicy: PolicyManifest = {
  version: '1.0',
  trustedIssuers: [
    {
      did: 'did:example:pharmacy-issuer',
      name: 'Test Pharmacy Issuer',
      credentialTypes: ['ePrescription'],
    },
  ],
  rules: [
    {
      id: 'pharmacy-rule',
      verifierPattern: 'did:example:pharmacy*',
      allowedClaims: ['medication', 'dosage', 'patientId'],
      requiresTrustedIssuer: true,
      requiresUserConsent: false,
    },
  ],
};

const baseRequest: VerifierRequest = {
  verifierId: 'did:example:pharmacy-berlin',
  requirements: [
    {
      credentialType: 'ePrescription',
      requestedClaims: ['medication', 'dosage'],
    },
  ],
};

const baseContext: EvaluationContext = {
  timestamp: Date.now(),
  userDID: 'did:example:patient-1',
};

function makeCred(overrides: Partial<StoredCredentialMetadata> = {}): StoredCredentialMetadata {
  return {
    id: 'cred-rx-1',
    issuer: 'did:example:pharmacy-issuer',
    type: ['ePrescription'],
    issuedAt: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
    claims: ['medication', 'dosage', 'patientId'],
    ...overrides,
  };
}

// --- Tests ---

describe('T-B2: ePrescription Single-Use Nullifier', () => {
  const engine = new PolicyEngine();

  it('active credential → normal evaluation (ALLOW)', async () => {
    const cred = makeCred({ status: 'active' });
    const result = await engine.evaluate(baseRequest, baseContext, [cred], basePolicy);

    expect(result.verdict).not.toBe('DENY');
    expect(result.reasonCodes).not.toContain(ReasonCode.CREDENTIAL_DISPENSED);
    expect(result.selectedCredentials).toContain('cred-rx-1');
  });

  it('dispensed credential → DENY + CREDENTIAL_DISPENSED', async () => {
    const cred = makeCred({ status: 'dispensed' });
    const result = await engine.evaluate(baseRequest, baseContext, [cred], basePolicy);

    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(ReasonCode.CREDENTIAL_DISPENSED);
  });

  it('revoked credential → DENY + CREDENTIAL_DISPENSED', async () => {
    const cred = makeCred({ status: 'revoked' });
    const result = await engine.evaluate(baseRequest, baseContext, [cred], basePolicy);

    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(ReasonCode.CREDENTIAL_DISPENSED);
  });

  it('multiple credentials, one dispensed one active → selects the active one', async () => {
    const dispensed = makeCred({ id: 'cred-rx-dispensed', status: 'dispensed' });
    const active = makeCred({ id: 'cred-rx-active', status: 'active' });
    const result = await engine.evaluate(baseRequest, baseContext, [dispensed, active], basePolicy);

    expect(result.verdict).not.toBe('DENY');
    expect(result.selectedCredentials).toContain('cred-rx-active');
    expect(result.selectedCredentials).not.toContain('cred-rx-dispensed');
  });

  it('no status field (undefined) → treated as active (backward compatible)', async () => {
    const cred = makeCred(); // no status field
    expect(cred.status).toBeUndefined();

    const result = await engine.evaluate(baseRequest, baseContext, [cred], basePolicy);

    expect(result.verdict).not.toBe('DENY');
    expect(result.selectedCredentials).toContain('cred-rx-1');
  });
});
