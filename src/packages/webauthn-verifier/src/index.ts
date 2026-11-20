/**
 * @package @askmi/webauthn-verifier
 * @description Native WebAuthn verification for hardware-backed security
 *
 * Implements WebAuthn authentication verification with:
 * - Hardware-backed key verification
 * - Counter-based replay protection
 * - Challenge lifecycle management
 * - Origin binding for phishing resistance
 */

import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type {
  AuthenticatorInfo,
  VerificationResult,
  WebAuthnChallenge,
  SignedAssertion,
} from './types';

/**
 * WebAuthn Native Verifier
 *
 * Provides hardware-backed authentication verification using WebAuthn.
 * Keys are stored in platform authenticators (TouchID, Windows Hello, YubiKey)
 * and cannot be extracted, providing production-grade security.
 */
export class WebAuthnNativeVerifier {
  private rpID: string;
  private expectedOrigin: string;
  private authenticators: Map<string, AuthenticatorInfo>; // credentialID -> info
  private challenges: Map<string, WebAuthnChallenge>; // userDID -> challenge

  constructor(
    rpID: string = 'mitch.example.com',
    expectedOrigin: string = 'https://mitch.example.com'
  ) {
    this.rpID = rpID;
    this.expectedOrigin = expectedOrigin;
    this.authenticators = new Map();
    this.challenges = new Map();
  }

  /**
   * Generate and store a challenge for WebAuthn authentication
   *
   * Challenge lifecycle:
   * - Generated on-demand when authentication requested
   * - 5-minute expiry (configurable)
   * - Single-use (deleted after verification)
   * - Base64URL encoded for WebAuthn compatibility
   *
   * @param userDID - User's DID
   * @returns Challenge data including expiry timestamp
   */
  async generateChallenge(userDID: string): Promise<WebAuthnChallenge> {
    const challenge = this.generateRandomBase64URL(32);
    const now = Date.now();

    const challengeData: WebAuthnChallenge = {
      challenge,
      userDID,
      timestamp: now,
      expiresAt: now + 5 * 60 * 1000, // 5 minutes
    };

    this.challenges.set(userDID, challengeData);
    return challengeData;
  }

  /**
   * Register an authenticator (called after registration ceremony)
   *
   * This method should be called after the user completes the WebAuthn
   * registration ceremony on their device. The authenticator info includes
   * the credential ID and public key for future verifications.
   *
   * @param userDID - User's DID
   * @param authenticator - Authenticator information from registration
   */
  async registerAuthenticator(
    userDID: string,
    authenticator: AuthenticatorInfo
  ): Promise<void> {
    const credentialID = authenticator.credentialID.toString('base64url');
    this.authenticators.set(credentialID, {
      ...authenticator,
      counter: authenticator.counter,
    });
  }

  /**
   * Verify a WebAuthn assertion (authentication response)
   *
   * Verification steps:
   * 1. Check challenge exists and not expired
   * 2. Lookup authenticator by credential ID
   * 3. Reject challenge/origin mismatch and counter replay (reject-only pre-checks)
   * 4. Consume the challenge (single-use, also on failure)
   * 5. Verify the assertion signature against the registered COSE key, plus
   *    rpIdHash, UP/UV flags and type (API-05d)
   * 6. Update stored counter
   *
   * @param signedAssertion - WebAuthn assertion from client
   * @param userDID - User's DID
   * @returns Verification result with status and reason
   */
  async verifyAssertion(
    signedAssertion: SignedAssertion,
    userDID: string
  ): Promise<VerificationResult> {
    // 1. Get stored challenge
    const storedChallenge = this.challenges.get(userDID);
    if (!storedChallenge) {
      return { verified: false, reason: 'CHALLENGE_NOT_FOUND' };
    }

    // 2. Check expiry — distinguishes timeout (user didn't interact) from session loss
    if (Date.now() > storedChallenge.expiresAt) {
      this.challenges.delete(userDID);
      return { verified: false, reason: 'CHALLENGE_EXPIRED' };
    }

    // 3. Get authenticator info
    const credentialID = Buffer.from(signedAssertion.rawId, 'base64url').toString('base64url');
    const authenticator = this.authenticators.get(credentialID);

    if (!authenticator) {
      return { verified: false, reason: 'KEY_NOT_FOUND' };
    }

    // 4. Pre-checks on the (not yet authenticated) client data and counter.
    //    They only ever reject; acceptance requires the signature check in step 5.
    let clientData: { type?: string; challenge?: string; origin?: string };
    let newCounter: number;
    try {
      clientData = JSON.parse(
        Buffer.from(signedAssertion.response.clientDataJSON, 'base64url').toString()
      );
      const authData = Buffer.from(signedAssertion.response.authenticatorData, 'base64url');
      if (authData.length < 37) return { verified: false, reason: 'SIGNATURE_INVALID' };
      // Counter is at bytes 33-36 (after rpIdHash and flags)
      newCounter = authData.readUInt32BE(33);
    } catch {
      return { verified: false, reason: 'SIGNATURE_INVALID' };
    }

    if (clientData.challenge !== storedChallenge.challenge) {
      return { verified: false, reason: 'CHALLENGE_MISMATCH' };
    }
    // Origin binding (phishing protection)
    if (clientData.origin !== this.expectedOrigin) {
      return { verified: false, reason: 'SIGNATURE_INVALID' };
    }
    // Replay protection
    if (newCounter <= authenticator.counter) {
      return { verified: false, reason: 'COUNTER_REPLAY' };
    }

    // From here on the challenge is spent, whatever the outcome (single-use).
    this.challenges.delete(userDID);

    // 5. API-05d: cryptographic verification of the assertion. Checks the signature over
    //    authenticatorData || SHA-256(clientDataJSON) against the registered COSE public key,
    //    plus type 'webauthn.get', challenge, origin, rpIdHash, the UP/UV flags and counter.
    try {
      const { verified } = await verifyAuthenticationResponse({
        response: {
          id: signedAssertion.id,
          rawId: signedAssertion.rawId,
          response: {
            clientDataJSON: signedAssertion.response.clientDataJSON,
            authenticatorData: signedAssertion.response.authenticatorData,
            signature: signedAssertion.response.signature,
            ...(signedAssertion.response.userHandle
              ? { userHandle: signedAssertion.response.userHandle }
              : {}),
          },
          type: 'public-key',
          clientExtensionResults: {},
        },
        expectedChallenge: storedChallenge.challenge,
        expectedOrigin: this.expectedOrigin,
        expectedRPID: this.rpID,
        expectedType: 'webauthn.get',
        credential: {
          id: credentialID,
          publicKey: new Uint8Array(authenticator.credentialPublicKey),
          counter: authenticator.counter,
          transports: authenticator.transports,
        },
        requireUserVerification: true,
      });
      if (!verified) return { verified: false, reason: 'SIGNATURE_INVALID' };
    } catch {
      return { verified: false, reason: 'SIGNATURE_INVALID' };
    }

    // 6. Update stored counter only after a verified signature
    authenticator.counter = newCounter;
    this.authenticators.set(credentialID, authenticator);

    return {
      verified: true,
      newCounter,
    };
  }

  /**
   * Get authenticator info (for debugging)
   */
  getAuthenticatorInfo(credentialID: string): AuthenticatorInfo | undefined {
    return this.authenticators.get(credentialID);
  }

  /**
   * Get stored challenge for a user (for testing)
   */
  getChallenge(userDID: string): WebAuthnChallenge | undefined {
    return this.challenges.get(userDID);
  }

  /**
   * Clear expired challenges (should be called periodically)
   */
  clearExpiredChallenges(): number {
    const now = Date.now();
    let cleared = 0;

    for (const [userDID, challenge] of this.challenges.entries()) {
      if (now > challenge.expiresAt) {
        this.challenges.delete(userDID);
        cleared++;
      }
    }

    return cleared;
  }

  /**
   * Generate random Base64URL-encoded string
   */
  private generateRandomBase64URL(length: number): string {
    const buffer = new Uint8Array(length);

    // Use Node.js crypto or browser crypto
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(buffer);
    } else {
      // Fallback for Node.js without webcrypto
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const nodeCrypto = require('crypto');
      nodeCrypto.randomFillSync(buffer);
    }

    return Buffer.from(buffer).toString('base64url');
  }
}

export * from './types';
export * from './step-up-auth';
