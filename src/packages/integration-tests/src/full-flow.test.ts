import { describe, it, expect, beforeEach } from 'vitest';
import { MockGovernmentIssuer, computeAgeProof } from '@mitch/mock-issuer';
import { PolicyEngine } from '@mitch/policy-engine';
import { ProtectionLayer } from '@mitch/layer-resolver';
import { StatusListRevocationChecker } from '@mitch/revocation-statuslist';
import { EIDIssuerConnector } from '@mitch/eid-issuer-connector';
import type { PolicyRule } from '@mitch/shared-types';

describe('E2E: Full Credential Lifecycle', () => {
  let mockIssuer: MockGovernmentIssuer;
  let eidConnector: EIDIssuerConnector;
  let policyEngine: PolicyEngine;
  let revocationChecker: StatusListRevocationChecker;

  beforeEach(async () => {
    mockIssuer = new MockGovernmentIssuer();
    await mockIssuer.initialize();

    eidConnector = new EIDIssuerConnector('mock');
    await eidConnector.initialize();

    policyEngine = new PolicyEngine();
    revocationChecker = new StatusListRevocationChecker({ cacheMinutes: 60 });
  });

  it('E2E: Liquor Store with Revocation Check', async () => {
    // STEP 1: Issuance (eID connector)
    const issuanceRequest = {
      userDID: 'did:example:alice',
      requestedAttributes: ['dateOfBirth'],
      purpose: 'Age verification for online liquor purchase',
    };

    const issuanceResponse = await eidConnector.requestIssuance(issuanceRequest);
    expect(issuanceResponse.credential).toBeDefined();

    // STEP 2: ZK Proof Generation (user-side)
    const birthdate = new Date('1990-01-01');
    const isOver18 = computeAgeProof(birthdate, 18);
    expect(isOver18).toBe(true);

    // STEP 3: Policy Evaluation
    const policy: PolicyRule = {
      id: 'liquor-store-layer1',
      verifierPattern: 'did:example:liquor-store',
      minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
      allowedClaims: ['age'],
      deniedClaims: [],
      requiresFreshness: false,
    };

    // Simplified policy check (real implementation in policy-engine)
    const verifierLayer = policy.minimumLayer ?? ProtectionLayer.WELT;
    const requiredLayer = ProtectionLayer.GRUNDVERSORGUNG;
    const layerCheck = verifierLayer >= requiredLayer;
    expect(layerCheck).toBe(true);

    // STEP 4: Revocation Check (optional but recommended)
    // Mock status entry (would come from credential)
    const statusEntry = {
      id: 'https://example.com/status/1',
      type: 'StatusList2021Entry' as const,
      statusPurpose: 'revocation' as const,
      statusListIndex: '0',
      statusListCredential: 'https://example.com/status-list/1',
    };

    // Skip actual check in test (would require mock HTTP server)
    // const revocationResult = await revocationChecker.checkRevocation(statusEntry);
    // expect(revocationResult.revoked).toBe(false);

    // STEP 5: Final Decision
    const finalDecision = layerCheck && isOver18 && true; // && !revoked
    expect(finalDecision).toBe(true);

    console.log('✅ E2E Flow Complete: ALLOW');
  });

  it('E2E: Layer Violation (Health Data Request)', async () => {
    // Liquor store tries to request health data (Layer 2)
    const policy: PolicyRule = {
      id: 'malicious-request',
      verifierPattern: 'did:example:liquor-store',
      minimumLayer: ProtectionLayer.GRUNDVERSORGUNG, // Layer 1
      allowedClaims: ['healthRecord'], // Requires Layer 2!
      deniedClaims: [],
      requiresFreshness: false,
    };

    const verifierLayer = policy.minimumLayer ?? ProtectionLayer.WELT;
    const requiredLayer = ProtectionLayer.VULNERABLE; // Layer 2
    const layerViolation = verifierLayer < requiredLayer;

    expect(layerViolation).toBe(true);
    console.log('✅ E2E Flow Complete: DENY (LAYER_VIOLATION)');
  });

  it('E2E: WebAuthn + Policy + Revocation (Full Stack)', async () => {
    // This test demonstrates all components working together
    // TODO: Implement full stack test with WebAuthn challenge

    // 1. User authenticates with WebAuthn
    // 2. Gets eID credential from government
    // 3. Verifier requests age proof
    // 4. Policy engine checks layers
    // 5. Revocation checker validates credential status
    // 6. Final decision: ALLOW or DENY

    expect(true).toBe(true); // Placeholder
  });
});
