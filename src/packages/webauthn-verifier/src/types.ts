/**
 * @package @mitch/webauthn-verifier
 * @description Type definitions for WebAuthn verification
 */

export interface AuthenticatorInfo {
  credentialID: Buffer;
  credentialPublicKey: Buffer;
  counter: number;
  transports?: AuthenticatorTransport[];
}

export interface VerificationResult {
  verified: boolean;
  reason?: 'CHALLENGE_MISMATCH' | 'COUNTER_REPLAY' | 'SIGNATURE_INVALID' | 'KEY_NOT_FOUND';
  newCounter?: number;
}

export interface WebAuthnChallenge {
  challenge: string; // Base64URL encoded
  userDID: string;
  timestamp: number;
  expiresAt: number;
}

export interface SignedAssertion {
  id: string; // Credential ID
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  type: 'public-key';
}
