/**
 * E2E Test: Liquor Store Age Verification (Layer 1)
 *
 * Tests the complete flow from credential issuance to policy evaluation
 * for a real-world scenario: liquor store age verification.
 *
 * Demonstrates:
 * - Layer 1 (GRUNDVERSORGUNG) protection for age data
 * - ZK-Predicate: isOver18 without revealing exact birthdate
 * - Layer violation detection (store tries to access Layer 2 data)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import {
  MockGovernmentIssuer,
  computeAgeProof,
  createAgeProofPresentation,
} from '@mitch/mock-issuer';
import { ProtectionLayer, getMinimumLayerForData, includesLayer } from '@mitch/layer-resolver';
import type {
  PolicyManifest,
  PolicyRule,
  VerifierRequest,
  StoredCredentialMetadata,
} from '@mitch/shared-types';

describe('E2E: Liquor Store Age Verification (Layer 1)', () => {
  let policyEngine: PolicyEngine;
  let mockIssuer: MockGovernmentIssuer;

  beforeEach(async () => {
    policyEngine = new PolicyEngine();
    mockIssuer = new MockGovernmentIssuer();
    await mockIssuer.initialize();
  });

  it('✅ ALLOW: Store requests age, user is over 18', async () => {
    // 1. Mock Issuer stellt Credential aus
    const birthdate = new Date('1990-01-01');
    const userDID = 'did:example:user123';
    const credential = await mockIssuer.issueAgeCredential(birthdate, userDID);

    // 2. User erstellt ZK-Proof (isOver18 = true)
    const presentation = createAgeProofPresentation(credential, 18);
    expect(presentation.isOverAge).toBe(true);

    // 3. Policy Manifest für Liquor Store
    const policy: PolicyManifest = {
      version: '1.0.0',
      globalSettings: {
        blockUnknownVerifiers: false,
        requireConsentForAll: false,
      },
      rules: [
        {
          id: 'liquor-store-policy',
          verifierPattern: 'did:example:liquor-store',
          minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, // Layer 1
          allowedClaims: ['age'],
          provenClaims: ['isOver18'],
          deniedClaims: [],
          requiresTrustedIssuer: true,
          maxCredentialAgeDays: 365,
          requiresUserConsent: false,
          priority: 10,
        },
      ],
      trustedIssuers: [
        {
          did: mockIssuer.getDID(),
          name: 'Mock Government',
          credentialTypes: ['AgeCredential'],
        },
      ],
    };

    // 4. Verifier Request
    const request: VerifierRequest = {
      verifierId: 'did:example:liquor-store',
      origin: 'https://liquor-store.example.com',
      requestedClaims: ['age'],
      requestedProvenClaims: ['isOver18'],
      requirements: [
        {
          credentialType: 'AgeCredential',
          requestedClaims: ['age'],
          requestedProvenClaims: ['isOver18'],
        },
      ],
      nonce: 'test-nonce-123',
    };

    // 5. Stored Credentials (simulating wallet storage)
    const storedCredentials: StoredCredentialMetadata[] = [
      {
        id: 'cred-001',
        type: ['AgeCredential'],
        issuer: mockIssuer.getDID(),
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        claims: ['age', 'birthdate', 'isOver18'],
      },
    ];

    // 6. Evaluation Context
    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: userDID,
    };

    // 7. Policy Engine evaluiert
    const result = await policyEngine.evaluate(request, context, storedCredentials, policy);

    // ✅ ASSERT
    expect(result.verdict).toBe('ALLOW');
    expect(result.reasonCodes).toContain(ReasonCode.RULE_MATCHED);
    expect(result.reasonCodes).toContain(ReasonCode.CREDENTIAL_VALID);
    expect(result.selectedCredentials).toContain('cred-001');
  });

  it('❌ DENY: Store tries to request health data (Layer 2 violation)', async () => {
    const birthdate = new Date('1990-01-01');
    const userDID = 'did:example:user123';
    const credential = await mockIssuer.issueAgeCredential(birthdate, userDID);

    // Malicious store tries to request health data (Layer 2)
    const policy: PolicyManifest = {
      version: '1.0.0',
      globalSettings: {
        blockUnknownVerifiers: false,
      },
      rules: [
        {
          id: 'malicious-store-policy',
          verifierPattern: 'did:example:liquor-store',
          minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, // Layer 1 - NOT authorized for Layer 2 data!
          allowedClaims: ['healthRecord'], // ❌ healthRecord requires Layer 2!
          deniedClaims: [],
          requiresTrustedIssuer: false,
          priority: 10,
        },
      ],
      trustedIssuers: [
        {
          did: mockIssuer.getDID(),
          name: 'Mock Government',
          credentialTypes: ['AgeCredential'],
        },
      ],
    };

    const request: VerifierRequest = {
      verifierId: 'did:example:liquor-store',
      requestedClaims: ['healthRecord'],
      requirements: [
        {
          credentialType: 'HealthCredential',
          requestedClaims: ['healthRecord'],
          requestedProvenClaims: [],
        },
      ],
    };

    const storedCredentials: StoredCredentialMetadata[] = [
      {
        id: 'health-cred-001',
        type: ['HealthCredential'],
        issuer: 'did:example:hospital',
        issuedAt: new Date().toISOString(),
        claims: ['healthRecord'],
      },
    ];

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: userDID,
    };

    // Evaluate
    const result = await policyEngine.evaluate(request, context, storedCredentials, policy);

    // ✅ ASSERT: Should trigger LAYER_VIOLATION
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(ReasonCode.LAYER_VIOLATION);
  });

  it('❌ DENY: User is under 18', async () => {
    const birthdate = new Date('2010-01-01'); // Under 18
    const userDID = 'did:example:minor123';
    const credential = await mockIssuer.issueAgeCredential(birthdate, userDID);

    // Compute age proof
    const presentation = createAgeProofPresentation(credential, 18);

    // ✅ ASSERT: Age proof should be false
    expect(presentation.isOverAge).toBe(false);

    // In a real system, the wallet would refuse to create the presentation
    // or would create one with isOverAge: false, which the verifier would reject.
  });

  it('✅ ALLOW: Layer enforcement allows Layer 1 data for Layer 1 verifier', () => {
    // Directly test layer resolution
    const verifierLayer = ProtectionLayer.GRUNDVERSORGUNG; // Layer 1
    const ageLayer = getMinimumLayerForData('age'); // Layer 1

    expect(ageLayer).toBe(ProtectionLayer.GRUNDVERSORGUNG);
    expect(includesLayer(verifierLayer, ageLayer)).toBe(true);
  });

  it('❌ DENY: Layer enforcement blocks Layer 2 data for Layer 1 verifier', () => {
    // Directly test layer resolution
    const verifierLayer = ProtectionLayer.GRUNDVERSORGUNG; // Layer 1
    const healthLayer = getMinimumLayerForData('healthRecord'); // Layer 2

    expect(healthLayer).toBe(ProtectionLayer.VULNERABLE);
    expect(includesLayer(verifierLayer, healthLayer)).toBe(false);
  });

  it('✅ ALLOW: Layer 2 verifier can access Layer 1 data (inheritance)', () => {
    // Layer 2 includes Layer 1 protections, so can access Layer 1 data
    const verifierLayer = ProtectionLayer.VULNERABLE; // Layer 2
    const ageLayer = getMinimumLayerForData('age'); // Layer 1

    expect(includesLayer(verifierLayer, ageLayer)).toBe(true);
  });

  it('✅ ALLOW: Multiple age thresholds (21+ for US liquor stores)', async () => {
    const birthdate = new Date('1995-06-15');
    const userDID = 'did:example:user456';
    const credential = await mockIssuer.issueAgeCredential(birthdate, userDID);

    // Test different age thresholds
    const over18 = createAgeProofPresentation(credential, 18);
    const over21 = createAgeProofPresentation(credential, 21);

    expect(over18.isOverAge).toBe(true);
    expect(over21.isOverAge).toBe(true);
  });

  it('❌ DENY: Age threshold not met for 21+ requirement', async () => {
    const birthdate = new Date('2007-01-01'); // 19 years old
    const userDID = 'did:example:young-user';
    const credential = await mockIssuer.issueAgeCredential(birthdate, userDID);

    const over18 = createAgeProofPresentation(credential, 18);
    const over21 = createAgeProofPresentation(credential, 21);

    expect(over18.isOverAge).toBe(true); // ✅ Over 18
    expect(over21.isOverAge).toBe(false); // ❌ Not yet 21
  });
});

describe('Layer Resolution Integration', () => {
  it('should correctly classify data by layer', () => {
    expect(getMinimumLayerForData('age')).toBe(ProtectionLayer.GRUNDVERSORGUNG);
    expect(getMinimumLayerForData('birthDate')).toBe(ProtectionLayer.GRUNDVERSORGUNG);
    expect(getMinimumLayerForData('education')).toBe(ProtectionLayer.GRUNDVERSORGUNG);

    expect(getMinimumLayerForData('healthRecord')).toBe(ProtectionLayer.VULNERABLE);
    expect(getMinimumLayerForData('medicalHistory')).toBe(ProtectionLayer.VULNERABLE);
    expect(getMinimumLayerForData('financialData')).toBe(ProtectionLayer.VULNERABLE);

    expect(getMinimumLayerForData('consent')).toBe(ProtectionLayer.WELT);
    expect(getMinimumLayerForData('publicKey')).toBe(ProtectionLayer.WELT);
  });

  it('should enforce layer inheritance (Layer 2 includes Layer 1 and 0)', () => {
    const layer2 = ProtectionLayer.VULNERABLE;

    expect(includesLayer(layer2, ProtectionLayer.WELT)).toBe(true);
    expect(includesLayer(layer2, ProtectionLayer.GRUNDVERSORGUNG)).toBe(true);
    expect(includesLayer(layer2, ProtectionLayer.VULNERABLE)).toBe(true);
  });

  it('should reject insufficient layer (Layer 1 cannot access Layer 2)', () => {
    const layer1 = ProtectionLayer.GRUNDVERSORGUNG;

    expect(includesLayer(layer1, ProtectionLayer.WELT)).toBe(true);
    expect(includesLayer(layer1, ProtectionLayer.GRUNDVERSORGUNG)).toBe(true);
    expect(includesLayer(layer1, ProtectionLayer.VULNERABLE)).toBe(false); // ❌
  });
});
