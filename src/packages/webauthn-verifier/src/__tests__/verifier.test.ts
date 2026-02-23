import { describe, it, expect, beforeEach } from 'vitest';
import { WebAuthnNativeVerifier } from '../index';
import type { AuthenticatorInfo } from '../types';

describe('WebAuthnNativeVerifier', () => {
  let verifier: WebAuthnNativeVerifier;

  beforeEach(() => {
    verifier = new WebAuthnNativeVerifier();
  });

  it('should generate challenge with expiry', async () => {
    const userDID = 'did:example:user123';
    const challenge = await verifier.generateChallenge(userDID);

    expect(challenge.challenge).toBeDefined();
    expect(challenge.challenge.length).toBeGreaterThan(32);
    expect(challenge.userDID).toBe(userDID);
    expect(challenge.expiresAt).toBeGreaterThan(Date.now());
    expect(challenge.expiresAt - challenge.timestamp).toBe(5 * 60 * 1000); // 5 minutes
  });

  it('should register authenticator', async () => {
    const userDID = 'did:example:user123';
    const authenticator: AuthenticatorInfo = {
      credentialID: Buffer.from('test-credential-id'),
      credentialPublicKey: Buffer.from('test-public-key'),
      counter: 0,
    };

    await verifier.registerAuthenticator(userDID, authenticator);

    const stored = verifier.getAuthenticatorInfo(
      authenticator.credentialID.toString('base64url')
    );
    expect(stored).toBeDefined();
    expect(stored?.counter).toBe(0);
  });

  it('should reject missing challenge', async () => {
    const userDID = 'did:example:user123';

    const signedAssertion = {
      id: 'test-id',
      rawId: Buffer.from('test-credential-id').toString('base64url'),
      response: {
        clientDataJSON: Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: 'wrong-challenge',
          origin: 'https://mitch.example.com',
        })).toString('base64url'),
        authenticatorData: Buffer.alloc(37).toString('base64url'), // Minimal auth data
        signature: 'test-signature',
      },
      type: 'public-key' as const,
    };

    const result = await verifier.verifyAssertion(signedAssertion, userDID);

    expect(result.verified).toBe(false);
    expect(result.reason).toBe('CHALLENGE_MISMATCH');
  });

  it('should reject expired challenge', async () => {
    const userDID = 'did:example:user123';

    // Generate challenge
    const challenge = await verifier.generateChallenge(userDID);

    // Manually expire the challenge
    const storedChallenge = verifier.getChallenge(userDID);
    if (storedChallenge) {
      storedChallenge.expiresAt = Date.now() - 1000; // Expired 1 second ago
    }

    const signedAssertion = {
      id: 'test-id',
      rawId: Buffer.from('test-credential-id').toString('base64url'),
      response: {
        clientDataJSON: Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin: 'https://mitch.example.com',
        })).toString('base64url'),
        authenticatorData: Buffer.alloc(37).toString('base64url'),
        signature: 'test-signature',
      },
      type: 'public-key' as const,
    };

    const result = await verifier.verifyAssertion(signedAssertion, userDID);

    expect(result.verified).toBe(false);
    expect(result.reason).toBe('CHALLENGE_MISMATCH');
  });

  it('should reject unknown authenticator', async () => {
    const userDID = 'did:example:user123';

    // Generate challenge but don't register authenticator
    const challenge = await verifier.generateChallenge(userDID);

    const signedAssertion = {
      id: 'unknown-id',
      rawId: Buffer.from('unknown-credential').toString('base64url'),
      response: {
        clientDataJSON: Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin: 'https://mitch.example.com',
        })).toString('base64url'),
        authenticatorData: Buffer.alloc(37).toString('base64url'),
        signature: 'test-signature',
      },
      type: 'public-key' as const,
    };

    const result = await verifier.verifyAssertion(signedAssertion, userDID);

    expect(result.verified).toBe(false);
    expect(result.reason).toBe('KEY_NOT_FOUND');
  });

  it('should clear expired challenges', async () => {
    const userDID1 = 'did:example:user1';
    const userDID2 = 'did:example:user2';

    // Generate two challenges
    await verifier.generateChallenge(userDID1);
    await verifier.generateChallenge(userDID2);

    // Expire one challenge
    const challenge1 = verifier.getChallenge(userDID1);
    if (challenge1) {
      challenge1.expiresAt = Date.now() - 1000;
    }

    // Clear expired challenges
    const cleared = verifier.clearExpiredChallenges();

    expect(cleared).toBe(1);
    expect(verifier.getChallenge(userDID1)).toBeUndefined();
    expect(verifier.getChallenge(userDID2)).toBeDefined();
  });

  it('should generate unique challenges', async () => {
    const userDID = 'did:example:user123';

    const challenge1 = await verifier.generateChallenge(userDID);
    const challenge2 = await verifier.generateChallenge(userDID); // Overwrites previous

    expect(challenge1.challenge).not.toBe(challenge2.challenge);
    expect(verifier.getChallenge(userDID)?.challenge).toBe(challenge2.challenge);
  });

  it('should validate counter increment', async () => {
    const userDID = 'did:example:user123';

    // Register authenticator
    const credentialID = Buffer.from('test-credential');
    const authenticator: AuthenticatorInfo = {
      credentialID,
      credentialPublicKey: Buffer.from('test-public-key'),
      counter: 5,
    };
    await verifier.registerAuthenticator(userDID, authenticator);

    // Generate challenge
    const challenge = await verifier.generateChallenge(userDID);

    // Create auth data with counter = 6 (incremented)
    const authData = Buffer.alloc(37);
    authData.writeUInt32BE(6, 33); // Counter at bytes 33-36

    const signedAssertion = {
      id: 'test-id',
      rawId: credentialID.toString('base64url'),
      response: {
        clientDataJSON: Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin: 'https://mitch.example.com',
        })).toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: 'test-signature',
      },
      type: 'public-key' as const,
    };

    const result = await verifier.verifyAssertion(signedAssertion, userDID);

    expect(result.verified).toBe(true);
    expect(result.newCounter).toBe(6);

    // Verify stored counter was updated
    const updatedAuth = verifier.getAuthenticatorInfo(credentialID.toString('base64url'));
    expect(updatedAuth?.counter).toBe(6);
  });

  it('should reject counter replay attack', async () => {
    const userDID = 'did:example:user123';

    // Register authenticator with counter = 5
    const credentialID = Buffer.from('test-credential');
    const authenticator: AuthenticatorInfo = {
      credentialID,
      credentialPublicKey: Buffer.from('test-public-key'),
      counter: 5,
    };
    await verifier.registerAuthenticator(userDID, authenticator);

    // Generate challenge
    const challenge = await verifier.generateChallenge(userDID);

    // Create auth data with counter = 4 (replay attempt!)
    const authData = Buffer.alloc(37);
    authData.writeUInt32BE(4, 33); // Counter not incremented

    const signedAssertion = {
      id: 'test-id',
      rawId: credentialID.toString('base64url'),
      response: {
        clientDataJSON: Buffer.from(JSON.stringify({
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin: 'https://mitch.example.com',
        })).toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: 'test-signature',
      },
      type: 'public-key' as const,
    };

    const result = await verifier.verifyAssertion(signedAssertion, userDID);

    expect(result.verified).toBe(false);
    expect(result.reason).toBe('COUNTER_REPLAY');
  });
});
