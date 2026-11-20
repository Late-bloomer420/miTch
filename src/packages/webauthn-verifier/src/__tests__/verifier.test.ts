import { describe, it, expect, beforeEach } from 'vitest';
import { WebAuthnNativeVerifier } from '../index';
import type { AuthenticatorInfo } from '../types';
import { createSoftAuthenticator } from './helpers/real-authenticator';

const RP_ID = 'mitch.example.com';
const ORIGIN = 'https://mitch.example.com';

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
    expect(result.reason).toBe('CHALLENGE_NOT_FOUND');
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
    expect(result.reason).toBe('CHALLENGE_EXPIRED');
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

  it('should validate counter increment (real signature)', async () => {
    const userDID = 'did:example:user123';
    const auth = createSoftAuthenticator('test-credential');
    await verifier.registerAuthenticator(userDID, {
      credentialID: auth.credentialID,
      credentialPublicKey: auth.credentialPublicKey,
      counter: 5,
    });
    const challenge = await verifier.generateChallenge(userDID);
    const result = await verifier.verifyAssertion(
      auth.assert({ challenge: challenge.challenge, origin: ORIGIN, rpID: RP_ID, counter: 6 }),
      userDID
    );
    expect(result.verified).toBe(true);
    expect(result.newCounter).toBe(6);
    expect(verifier.getAuthenticatorInfo(auth.credentialID.toString('base64url'))?.counter).toBe(6);
    expect(verifier.getChallenge(userDID)).toBeUndefined();
  });

  it('should reject counter replay attack', async () => {
    const userDID = 'did:example:user123';
    const auth = createSoftAuthenticator('test-credential');
    await verifier.registerAuthenticator(userDID, {
      credentialID: auth.credentialID,
      credentialPublicKey: auth.credentialPublicKey,
      counter: 5,
    });
    const challenge = await verifier.generateChallenge(userDID);
    const result = await verifier.verifyAssertion(
      auth.assert({ challenge: challenge.challenge, origin: ORIGIN, rpID: RP_ID, counter: 4 }),
      userDID
    );
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('COUNTER_REPLAY');
  });

  describe('API-05d: server-side assertion signature', () => {
    async function setup(counter = 0) {
      const userDID = 'did:example:sig';
      const auth = createSoftAuthenticator('sig-credential');
      await verifier.registerAuthenticator(userDID, {
        credentialID: auth.credentialID,
        credentialPublicKey: auth.credentialPublicKey,
        counter,
      });
      const challenge = await verifier.generateChallenge(userDID);
      return { userDID, auth, challenge: challenge.challenge };
    }

    it('rejects a forged signature (the pre-fix code accepted any signature bytes)', async () => {
      const { userDID, auth, challenge } = await setup();
      const assertion = auth.assert({ challenge, origin: ORIGIN, rpID: RP_ID, counter: 1 });
      assertion.response.signature = Buffer.from('test-signature').toString('base64url');
      const result = await verifier.verifyAssertion(assertion, userDID);
      expect(result).toEqual({ verified: false, reason: 'SIGNATURE_INVALID' });
      // Counter is not advanced by a failed attempt; the challenge is spent.
      expect(verifier.getAuthenticatorInfo(auth.credentialID.toString('base64url'))?.counter).toBe(0);
      expect(verifier.getChallenge(userDID)).toBeUndefined();
    });

    it('rejects a signature from a different key', async () => {
      const { userDID, challenge } = await setup();
      const attacker = createSoftAuthenticator('sig-credential');
      const result = await verifier.verifyAssertion(
        attacker.assert({ challenge, origin: ORIGIN, rpID: RP_ID, counter: 1 }),
        userDID
      );
      expect(result).toEqual({ verified: false, reason: 'SIGNATURE_INVALID' });
    });

    it('rejects a validly signed assertion for another RP ID (rpIdHash)', async () => {
      const { userDID, auth, challenge } = await setup();
      const result = await verifier.verifyAssertion(
        auth.assert({ challenge, origin: ORIGIN, rpID: 'evil.example.com', counter: 1 }),
        userDID
      );
      expect(result).toEqual({ verified: false, reason: 'SIGNATURE_INVALID' });
    });

    it('rejects a validly signed assertion without user presence/verification flags', async () => {
      const { userDID, auth, challenge } = await setup();
      const result = await verifier.verifyAssertion(
        auth.assert({ challenge, origin: ORIGIN, rpID: RP_ID, counter: 1, flags: 0x00 }),
        userDID
      );
      expect(result).toEqual({ verified: false, reason: 'SIGNATURE_INVALID' });
    });

    it('rejects a validly signed registration-type client data', async () => {
      const { userDID, auth, challenge } = await setup();
      const result = await verifier.verifyAssertion(
        auth.assert({ challenge, origin: ORIGIN, rpID: RP_ID, counter: 1, type: 'webauthn.create' }),
        userDID
      );
      expect(result).toEqual({ verified: false, reason: 'SIGNATURE_INVALID' });
    });

    it('rejects a second use of the same challenge', async () => {
      const { userDID, auth, challenge } = await setup();
      const first = auth.assert({ challenge, origin: ORIGIN, rpID: RP_ID, counter: 1 });
      expect((await verifier.verifyAssertion(first, userDID)).verified).toBe(true);
      const second = auth.assert({ challenge, origin: ORIGIN, rpID: RP_ID, counter: 2 });
      expect(await verifier.verifyAssertion(second, userDID)).toEqual({
        verified: false,
        reason: 'CHALLENGE_NOT_FOUND',
      });
    });
  });
});
