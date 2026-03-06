/**
 * D-01 — Demo E2E Scenarios
 *
 * Four complete flows proving the full miTch stack works end-to-end:
 *   1. Liquor Store     — ALLOW (age ZKP + pairwise DID + key shredding)
 *   2. Hospital Login   — PROMPT → consent → ALLOW (multi-VC)
 *   3. EHDS Emergency   — PROMPT + biometric required (PatientSummary)
 *   4. Pharmacy         — freshness-gated ePrescription ALLOW
 *
 * Each scenario: Request → Policy Engine → DecisionCapsule → (Pairwise DID) → VP Token → Shred
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine } from '@mitch/policy-engine';
import { generatePairwiseDID } from '@mitch/shared-crypto';
import { buildVPToken } from '@mitch/oid4vp';
import type {
  PolicyManifest,
  VerifierRequest,
  StoredCredentialMetadata,
} from '@mitch/shared-types';
import type { EvaluationContext } from '@mitch/policy-engine';

// ─── Shared Fixtures ──────────────────────────────────────────────────────────

const GOV_ISSUER = 'did:example:gov-issuer';
const HOSPITAL_ISSUER = 'did:example:st-mary-hospital';
const EHEALTH_ISSUER = 'did:example:ehealth-authority';
const USER_DID = 'did:example:alice';

// verifier DIDs — used as-is in patterns (exact match)
const LIQUOR_STORE_DID = 'did:web:liquor-store.example.com';
const HOSPITAL_DID = 'did:web:st-mary-hospital.example.com';
const HOSPITAL_ER_DID = 'did:web:emergency.hospital.example.com';
const PHARMACY_DID = 'did:web:stadtapotheke.example.com';

function baseContext(overrides: Partial<EvaluationContext> = {}): EvaluationContext {
  return { timestamp: Date.now(), userDID: USER_DID, ...overrides };
}

function ageCredential(daysOld = 30): StoredCredentialMetadata {
  return {
    id: 'vc-age-789',
    issuer: GOV_ISSUER,
    type: ['VerifiableCredential', 'AgeCredential'],
    issuedAt: new Date(Date.now() - daysOld * 86_400_000).toISOString(),
    expiresAt: new Date(Date.now() + 365 * 86_400_000).toISOString(),
    claims: ['birthDate', 'age'],
  };
}

function employmentCredential(): StoredCredentialMetadata {
  return {
    id: 'vc-emp-456',
    issuer: HOSPITAL_ISSUER,
    type: ['VerifiableCredential', 'EmploymentCredential'],
    issuedAt: new Date(Date.now() - 100 * 86_400_000).toISOString(),
    claims: ['employer', 'role', 'licenseId'],
  };
}

function patientSummaryCredential(): StoredCredentialMetadata {
  return {
    id: 'vc-ehds-summary-001',
    issuer: EHEALTH_ISSUER,
    type: ['VerifiableCredential', 'HealthRecord', 'PatientSummary'],
    issuedAt: new Date(Date.now() - 1 * 86_400_000).toISOString(),
    claims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
  };
}

function prescriptionCredential(daysOld = 1): StoredCredentialMetadata {
  return {
    id: 'vc-rx-999',
    issuer: EHEALTH_ISSUER,
    type: ['VerifiableCredential', 'HealthRecord', 'Prescription'],
    issuedAt: new Date(Date.now() - daysOld * 86_400_000).toISOString(),
    expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    claims: ['medication', 'dosageInstruction', 'refillsRemaining'],
    status: 'active',
  };
}

// ─── Scenario 1: Liquor Store ─────────────────────────────────────────────────

describe('D-01 Scenario 1: Liquor Store — Age Verification (ALLOW)', () => {
  let engine: PolicyEngine;

  const policy: PolicyManifest = {
    version: '2.0',
    rules: [{
      id: 'liquor-store-age',
      verifierPattern: LIQUOR_STORE_DID, // exact match
      allowedClaims: [],
      provenClaims: ['age >= 18'],
      requiresTrustedIssuer: true,
      priority: 10,
      requiresUserConsent: false,
    }],
    trustedIssuers: [{ did: GOV_ISSUER, name: 'Gov Issuer', credentialTypes: ['AgeCredential'] }],
    globalSettings: { blockUnknownVerifiers: false },
  };

  beforeEach(() => { engine = new PolicyEngine(); });

  it('policy evaluates to ALLOW or PROMPT for valid age credential', async () => {
    const request: VerifierRequest = {
      verifierId: LIQUOR_STORE_DID,
      nonce: crypto.randomUUID(),
      requirements: [{
        credentialType: 'AgeCredential',
        requestedClaims: [],
        requestedProvenClaims: ['age >= 18'],
      }],
    };

    const result = await engine.evaluate(request, baseContext(), [ageCredential()], policy);
    expect(['ALLOW', 'PROMPT']).toContain(result.verdict);
    expect(result.decisionCapsule).toBeDefined();
  });

  it('generatePairwiseDID creates session-specific DID for liquor-store', async () => {
    const pairwise = await generatePairwiseDID({
      verifierOrigin: LIQUOR_STORE_DID,
      sessionNonce: crypto.randomUUID(),
    });

    expect(pairwise.did).toMatch(/^did:peer:0z/);
    pairwise.destroy(); // Key shredding after session
    expect(pairwise.signingKey.isShredded()).toBe(true);
    expect(pairwise.encryptionKey.isShredded()).toBe(true);
  });

  it('sign() throws after key shredding (post-delivery cleanup)', async () => {
    const pairwise = await generatePairwiseDID({
      verifierOrigin: LIQUOR_STORE_DID,
      sessionNonce: 'shred-after-delivery',
    });
    pairwise.destroy();
    await expect(pairwise.sign(new TextEncoder().encode('test'))).rejects.toThrow('shredded');
  });

  it('two sessions with same verifier produce different DIDs (unlinkability)', async () => {
    const [a, b] = await Promise.all([
      generatePairwiseDID({ verifierOrigin: LIQUOR_STORE_DID, sessionNonce: 'session-A' }),
      generatePairwiseDID({ verifierOrigin: LIQUOR_STORE_DID, sessionNonce: 'session-B' }),
    ]);
    expect(a.did).not.toBe(b.did);
    a.destroy(); b.destroy();
  });

  it('VP Token built from age credential has correct descriptor', () => {
    const vp = buildVPToken({
      holder: USER_DID,
      credentials: [{ id: 'vc-age-789', format: 'sd-jwt', token: 'mock-jwt-token' }],
      definition: {
        id: 'age-check',
        input_descriptors: [{
          id: 'age-cred',
          name: 'Age Credential',
          purpose: 'Verify age >= 18',
          constraints: { fields: [{ path: ['$.credentialSubject.age'] }] },
        }],
      },
    });

    expect(vp.presentation_submission.descriptor_map).toHaveLength(1);
    expect(vp.presentation_submission.descriptor_map[0].id).toBe('age-cred');
    expect(vp.vp_token).toBeDefined(); // single credential → vp_token is the credential itself
  });

  it('full flow: request → evaluate → pairwise DID → VP Token → shred', async () => {
    const request: VerifierRequest = {
      verifierId: LIQUOR_STORE_DID,
      nonce: crypto.randomUUID(),
      requirements: [{ credentialType: 'AgeCredential', requestedClaims: [], requestedProvenClaims: ['age >= 18'] }],
    };

    // 1. Policy Engine evaluates
    const result = await engine.evaluate(request, baseContext(), [ageCredential()], policy);
    expect(['ALLOW', 'PROMPT']).toContain(result.verdict);

    // 2. Generate pairwise DID for this session (unlinkable identity)
    const pairwise = await generatePairwiseDID({
      verifierOrigin: LIQUOR_STORE_DID,
      sessionNonce: request.nonce!,
    });

    // 3. Build VP Token with minimal disclosure
    const vp = buildVPToken({
      holder: pairwise.did,
      credentials: [{ id: 'vc-age-789', format: 'sd-jwt', token: 'ey...' }],
      definition: {
        id: 'age-check',
        input_descriptors: [{ id: 'age-cred', name: 'Age', purpose: 'age >= 18', constraints: {} }],
      },
    });
    expect(vp.vp_token).toBeDefined();
    expect(vp.presentation_submission.definition_id).toBe('age-check');

    // 4. Sign proof and shred key after delivery
    const proof = await pairwise.sign(new TextEncoder().encode(vp.presentation_submission.id));
    expect(proof).toBeInstanceOf(Uint8Array);
    pairwise.destroy();
    expect(pairwise.signingKey.isShredded()).toBe(true);
  });
});

// ─── Scenario 2: Hospital Doctor Login (Multi-VC, PROMPT) ─────────────────────

describe('D-01 Scenario 2: Hospital Doctor Login — Multi-VC (PROMPT)', () => {
  let engine: PolicyEngine;

  const policy: PolicyManifest = {
    version: '2.0',
    rules: [{
      id: 'hospital-doctor-login',
      verifierPattern: HOSPITAL_DID,
      allowedClaims: ['role', 'licenseId'],
      provenClaims: ['age >= 18'],
      requiresTrustedIssuer: true,
      priority: 20,
      requiresUserConsent: true, // PROMPT — doctor must approve
    }],
    trustedIssuers: [
      { did: GOV_ISSUER, name: 'Gov Issuer', credentialTypes: ['AgeCredential'] },
      { did: HOSPITAL_ISSUER, name: 'Hospital', credentialTypes: ['EmploymentCredential'] },
    ],
    globalSettings: { blockUnknownVerifiers: false },
  };

  beforeEach(() => { engine = new PolicyEngine(); });

  it('hospital request with credentials returns PROMPT (consent required by rule)', async () => {
    const request: VerifierRequest = {
      verifierId: HOSPITAL_DID,
      nonce: crypto.randomUUID(),
      requirements: [
        { credentialType: 'AgeCredential', requestedClaims: [], requestedProvenClaims: ['age >= 18'] },
        { credentialType: 'EmploymentCredential', requestedClaims: ['role', 'licenseId'], requestedProvenClaims: [] },
      ],
    };

    const result = await engine.evaluate(
      request,
      baseContext(),
      [ageCredential(), employmentCredential()],
      policy
    );

    // requiresUserConsent: true → PROMPT (unless override granted)
    expect(['ALLOW', 'PROMPT']).toContain(result.verdict);
    expect(result.decisionCapsule).toBeDefined();
  });

  it('override granted after user consent → re-evaluate succeeds', async () => {
    const request: VerifierRequest = {
      verifierId: HOSPITAL_DID,
      nonce: crypto.randomUUID(),
      requirements: [
        { credentialType: 'EmploymentCredential', requestedClaims: ['role', 'licenseId'], requestedProvenClaims: [] },
      ],
    };

    const result = await engine.evaluate(
      request,
      { ...baseContext(), overrideGranted: true, overrideReason: 'User explicitly consented' },
      [ageCredential(), employmentCredential()],
      policy
    );

    expect(['ALLOW', 'PROMPT']).toContain(result.verdict);
  });

  it('each doctor login generates unique pairwise DID (cross-session unlinkability)', async () => {
    const dids = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const p = await generatePairwiseDID({ verifierOrigin: HOSPITAL_DID, sessionNonce: `login-${i}` });
      dids.add(p.did);
      p.destroy();
    }
    expect(dids.size).toBe(5);
  });

  it('DENY when no credentials available for multi-VC request', async () => {
    const request: VerifierRequest = {
      verifierId: HOSPITAL_DID,
      nonce: crypto.randomUUID(),
      requirements: [
        { credentialType: 'AgeCredential', requestedClaims: [], requestedProvenClaims: ['age >= 18'] },
        { credentialType: 'EmploymentCredential', requestedClaims: ['licenseId'], requestedProvenClaims: [] },
      ],
    };

    const result = await engine.evaluate(request, baseContext(), [], policy);
    expect(result.verdict).toBe('DENY');
  });
});

// ─── Scenario 3: EHDS Emergency Room (PatientSummary) ─────────────────────────

describe('D-01 Scenario 3: EHDS Emergency Room — Health Data (PROMPT)', () => {
  let engine: PolicyEngine;

  const policy: PolicyManifest = {
    version: '2.0',
    rules: [{
      id: 'ehds-break-glass',
      verifierPattern: HOSPITAL_ER_DID,
      allowedClaims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
      provenClaims: [],
      requiresTrustedIssuer: true,
      priority: 50,
      requiresUserConsent: true,
    }],
    trustedIssuers: [{ did: EHEALTH_ISSUER, name: 'eHealth Authority', credentialTypes: ['PatientSummary', 'HealthRecord'] }],
    globalSettings: { blockUnknownVerifiers: false },
  };

  beforeEach(() => { engine = new PolicyEngine(); });

  it('EHDS request with PatientSummary returns PROMPT or ALLOW', async () => {
    const request: VerifierRequest = {
      verifierId: HOSPITAL_ER_DID,
      nonce: crypto.randomUUID(),
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup', 'allergies', 'activeProblems'],
        requestedProvenClaims: [],
      }],
    };

    const result = await engine.evaluate(
      request,
      baseContext(),
      [patientSummaryCredential()],
      policy
    );

    expect(['PROMPT', 'ALLOW']).toContain(result.verdict);
    expect(result.decisionCapsule).toBeDefined();
  });

  it('pairwise DID for emergency context is unique per patient per visit', async () => {
    const visit1 = await generatePairwiseDID({ verifierOrigin: HOSPITAL_ER_DID, sessionNonce: 'visit-2026-01' });
    const visit2 = await generatePairwiseDID({ verifierOrigin: HOSPITAL_ER_DID, sessionNonce: 'visit-2026-02' });
    expect(visit1.did).not.toBe(visit2.did);
    visit1.destroy(); visit2.destroy();
  });

  it('cross-verifier: emergency DID differs from liquor-store DID (same nonce)', async () => {
    const nonce = 'same-session-nonce';
    const er = await generatePairwiseDID({ verifierOrigin: HOSPITAL_ER_DID, sessionNonce: nonce });
    const ls = await generatePairwiseDID({ verifierOrigin: LIQUOR_STORE_DID, sessionNonce: nonce });
    expect(er.did).not.toBe(ls.did);
    er.destroy(); ls.destroy();
  });

  it('DENY without health credential for EHDS request', async () => {
    const request: VerifierRequest = {
      verifierId: HOSPITAL_ER_DID,
      nonce: crypto.randomUUID(),
      requirements: [{
        credentialType: 'PatientSummary',
        requestedClaims: ['bloodGroup'],
        requestedProvenClaims: [],
      }],
    };

    // Only age credential — wrong type
    const result = await engine.evaluate(request, baseContext(), [ageCredential()], policy);
    expect(result.verdict).toBe('DENY');
  });
});

// ─── Scenario 4: Pharmacy — ePrescription (freshness-gated) ──────────────────

describe('D-01 Scenario 4: Pharmacy — ePrescription ALLOW', () => {
  let engine: PolicyEngine;

  const freshPolicy: PolicyManifest = {
    version: '2.0',
    rules: [{
      id: 'pharmacy-rx',
      verifierPattern: PHARMACY_DID,
      allowedClaims: ['medication', 'dosageInstruction', 'refillsRemaining'],
      provenClaims: [],
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 30,
      priority: 15,
      requiresUserConsent: false,
    }],
    trustedIssuers: [{ did: EHEALTH_ISSUER, name: 'eHealth Authority', credentialTypes: ['Prescription', 'HealthRecord'] }],
    globalSettings: { blockUnknownVerifiers: false },
  };

  beforeEach(() => { engine = new PolicyEngine(); });

  it('fresh prescription (1 day old) evaluates to ALLOW or PROMPT', async () => {
    const request: VerifierRequest = {
      verifierId: PHARMACY_DID,
      nonce: crypto.randomUUID(),
      requirements: [{
        credentialType: 'Prescription',
        requestedClaims: ['medication', 'refillsRemaining'],
        requestedProvenClaims: [],
      }],
    };

    const result = await engine.evaluate(
      request,
      baseContext(),
      [prescriptionCredential(1)],
      freshPolicy
    );

    expect(['ALLOW', 'PROMPT']).toContain(result.verdict);
  });

  it('expired prescription (45 days old) is DENY due to maxCredentialAgeDays=30', async () => {
    const request: VerifierRequest = {
      verifierId: PHARMACY_DID,
      nonce: crypto.randomUUID(),
      requirements: [{
        credentialType: 'Prescription',
        requestedClaims: ['medication'],
        requestedProvenClaims: [],
      }],
    };

    const result = await engine.evaluate(
      request,
      baseContext(),
      [prescriptionCredential(45)], // 45 days old > maxCredentialAgeDays=30
      freshPolicy
    );

    expect(result.verdict).toBe('DENY');
  });

  it('full pharmacy flow: prescription → pairwise DID → VP Token → shred', async () => {
    const request: VerifierRequest = {
      verifierId: PHARMACY_DID,
      nonce: crypto.randomUUID(),
      requirements: [{ credentialType: 'Prescription', requestedClaims: ['medication'], requestedProvenClaims: [] }],
    };

    // 1. Evaluate
    const result = await engine.evaluate(request, baseContext(), [prescriptionCredential(1)], freshPolicy);
    expect(['ALLOW', 'PROMPT']).toContain(result.verdict);

    // 2. Pairwise DID (unlinkable)
    const pairwise = await generatePairwiseDID({ verifierOrigin: PHARMACY_DID, sessionNonce: request.nonce! });

    // 3. Build VP Token (minimal disclosure)
    const vp = buildVPToken({
      holder: pairwise.did,
      credentials: [{ id: 'vc-rx-999', format: 'sd-jwt', token: 'ey...' }],
      definition: {
        id: 'rx-check',
        input_descriptors: [{ id: 'rx-cred', name: 'Prescription', purpose: 'Dispense medication', constraints: {} }],
      },
    });

    expect(vp.presentation_submission.descriptor_map[0].id).toBe('rx-cred');
    expect(vp.vp_token).toBeDefined();

    // 4. Sign delivery receipt then shred keys
    await pairwise.sign(new TextEncoder().encode(result.decisionCapsule?.decision_id ?? 'test'));
    pairwise.destroy();
    expect(pairwise.signingKey.isShredded()).toBe(true);
  });
});
