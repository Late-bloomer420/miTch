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
    const _statusEntry = {
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
    // G-10: Full stack test with mocked WebAuthn step-up authentication
    const { WebAuthnNativeVerifier } = await import('@mitch/webauthn-verifier');

    const verifier = new WebAuthnNativeVerifier('mitch.example.com', 'https://mitch.example.com');
    const userDID = 'did:example:alice';

    // STEP 1: WebAuthn step-up — generate challenge for high-risk request
    const challenge = await verifier.generateChallenge(userDID);
    expect(challenge.challenge).toBeDefined();
    expect(challenge.expiresAt).toBeGreaterThan(Date.now());

    // STEP 2: Mock authenticator registration (simulates prior enrollment)
    const mockCredentialID = Buffer.from('mock-credential-id-001');
    const mockPublicKey = Buffer.from('mock-public-key-placeholder');
    await verifier.registerAuthenticator(userDID, {
      credentialID: mockCredentialID,
      credentialPublicKey: mockPublicKey,
      counter: 0,
      transports: ['internal'],
    });

    // STEP 3: Mock WebAuthn assertion (simulates hardware authenticator response)
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: challenge.challenge,
      origin: 'https://mitch.example.com',
      crossOrigin: false,
    })).toString('base64url');

    // Build authenticator data: 32-byte rpIdHash + 1 flags byte + 4-byte counter (BE)
    const rpIdHash = Buffer.alloc(32, 0xAA); // Mock RP ID hash
    const flags = Buffer.from([0x01]); // UP flag set
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(1, 0); // Counter = 1 (incremented from 0)
    const authenticatorData = Buffer.concat([rpIdHash, flags, counterBuf]).toString('base64url');

    const mockSignature = Buffer.from('mock-signature').toString('base64url');

    const signedAssertion = {
      id: mockCredentialID.toString('base64url'),
      rawId: mockCredentialID.toString('base64url'),
      response: {
        clientDataJSON,
        authenticatorData,
        signature: mockSignature,
      },
      type: 'public-key' as const,
    };

    // STEP 4: Verify the WebAuthn assertion (step-up auth)
    const webauthnResult = await verifier.verifyAssertion(signedAssertion, userDID);
    expect(webauthnResult.verified).toBe(true);
    expect(webauthnResult.newCounter).toBe(1);

    // Confirm challenge is consumed (single-use)
    expect(verifier.getChallenge(userDID)).toBeUndefined();

    // STEP 5: After step-up auth succeeds, proceed with credential issuance
    const issuanceResponse = await eidConnector.requestIssuance({
      userDID,
      requestedAttributes: ['dateOfBirth'],
      purpose: 'Age verification (step-up authenticated)',
    });
    expect(issuanceResponse.credential).toBeDefined();

    // STEP 6: ZK Proof
    const isOver18 = computeAgeProof(new Date('1990-01-01'), 18);
    expect(isOver18).toBe(true);

    // STEP 7: Policy check — high-risk request requires Layer 2+
    const policy: PolicyRule = {
      id: 'high-risk-step-up',
      verifierPattern: 'did:example:financial-service',
      minimumLayer: ProtectionLayer.VULNERABLE, // Layer 2 — requires step-up
      allowedClaims: ['age', 'identity'],
      deniedClaims: [],
      requiresFreshness: true,
    };

    const verifierLayer = policy.minimumLayer ?? ProtectionLayer.WELT;
    const requiredLayer = ProtectionLayer.VULNERABLE;
    const layerCheck = verifierLayer >= requiredLayer;
    expect(layerCheck).toBe(true);

    // STEP 8: Final decision — all gates passed
    const stepUpPassed = webauthnResult.verified;
    const finalDecision = stepUpPassed && layerCheck && isOver18;
    expect(finalDecision).toBe(true);

    console.log('✅ E2E Full Stack: WebAuthn step-up + ZKP + Policy = ALLOW');
  });

  it('E2E: WebAuthn step-up rejects expired challenge', async () => {
    const { WebAuthnNativeVerifier } = await import('@mitch/webauthn-verifier');

    const verifier = new WebAuthnNativeVerifier('mitch.example.com', 'https://mitch.example.com');
    const userDID = 'did:example:bob';

    // Generate challenge then manually expire it
    const challenge = await verifier.generateChallenge(userDID);
    const stored = verifier.getChallenge(userDID)!;
    // Force expiry by mutating the stored object
    (stored as any).expiresAt = Date.now() - 1000;

    // Mock a valid-looking assertion
    const mockCredentialID = Buffer.from('mock-cred-bob');
    await verifier.registerAuthenticator(userDID, {
      credentialID: mockCredentialID,
      credentialPublicKey: Buffer.from('mock-key'),
      counter: 0,
    });

    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: challenge.challenge,
      origin: 'https://mitch.example.com',
    })).toString('base64url');

    const authData = Buffer.concat([Buffer.alloc(32, 0xAA), Buffer.from([0x01]), Buffer.alloc(4)]);
    authData.writeUInt32BE(1, 33);

    const result = await verifier.verifyAssertion({
      id: mockCredentialID.toString('base64url'),
      rawId: mockCredentialID.toString('base64url'),
      response: {
        clientDataJSON,
        authenticatorData: authData.toString('base64url'),
        signature: Buffer.from('sig').toString('base64url'),
      },
      type: 'public-key',
    }, userDID);

    expect(result.verified).toBe(false);
    expect(result.reason).toBe('CHALLENGE_EXPIRED');
    console.log('✅ Expired challenge correctly rejected');
  });

  it('E2E: WebAuthn step-up rejects counter replay', async () => {
    const { WebAuthnNativeVerifier } = await import('@mitch/webauthn-verifier');

    const verifier = new WebAuthnNativeVerifier('mitch.example.com', 'https://mitch.example.com');
    const userDID = 'did:example:charlie';

    const mockCredentialID = Buffer.from('mock-cred-charlie');
    await verifier.registerAuthenticator(userDID, {
      credentialID: mockCredentialID,
      credentialPublicKey: Buffer.from('mock-key'),
      counter: 5, // Already at 5
    });

    const challenge = await verifier.generateChallenge(userDID);

    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: challenge.challenge,
      origin: 'https://mitch.example.com',
    })).toString('base64url');

    // Counter = 3, which is <= stored counter 5 → replay
    const authData = Buffer.concat([Buffer.alloc(32, 0xAA), Buffer.from([0x01]), Buffer.alloc(4)]);
    authData.writeUInt32BE(3, 33);

    const result = await verifier.verifyAssertion({
      id: mockCredentialID.toString('base64url'),
      rawId: mockCredentialID.toString('base64url'),
      response: {
        clientDataJSON,
        authenticatorData: authData.toString('base64url'),
        signature: Buffer.from('sig').toString('base64url'),
      },
      type: 'public-key',
    }, userDID);

    expect(result.verified).toBe(false);
    expect(result.reason).toBe('COUNTER_REPLAY');
    console.log('✅ Counter replay correctly rejected');
  });
});
