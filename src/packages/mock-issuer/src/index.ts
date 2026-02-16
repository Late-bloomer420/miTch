/**
 * @package @mitch/mock-issuer
 * @description Mock Government Issuer for testing miTch credential flows
 *
 * Implements SD-JWT-inspired credential issuance for MVP testing.
 * Uses JOSE for JWT signing with ES256 algorithm.
 */

import { SignJWT, generateKeyPair, exportJWK, importJWK, jwtVerify } from 'jose';
import type { JWK, KeyLike } from 'jose';

/**
 * Age Credential Claims Structure
 */
export interface AgeCredentialClaims {
  /** Issuer DID */
  iss: string;
  /** Subject DID (user) */
  sub: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Expiry (Unix timestamp) */
  exp: number;
  /** Birth date in ISO format (YYYY-MM-DD) - selectively disclosable */
  birthdate: string;
  /** Credential type */
  type: string;
}

/**
 * Issued Credential Structure
 */
export interface IssuedCredential {
  /** JWT token */
  jwt: string;
  /** Issuer public key (JWK format) */
  issuerPublicKey: JWK;
  /** Credential claims (for holder storage) */
  claims: AgeCredentialClaims;
}

/**
 * Mock Government Issuer
 *
 * Simulates a government eID issuer that can issue age credentials
 * with selective disclosure capabilities (birthdate can be hidden).
 */
export class MockGovernmentIssuer {
  private privateKey: KeyLike | null = null;
  private publicKey: KeyLike | null = null;
  private issuerDID: string;

  constructor(issuerDID?: string) {
    this.issuerDID = issuerDID || 'did:example:government-issuer';
  }

  /**
   * Initialize the issuer by generating ES256 keypair
   */
  async initialize(): Promise<void> {
    // Generate ES256 keypair for signing
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Issue an Age Credential for a user
   *
   * @param birthdate - User's birth date
   * @param userDID - User's DID
   * @returns Issued credential with JWT and public key
   */
  async issueAgeCredential(birthdate: Date, userDID: string): Promise<IssuedCredential> {
    if (!this.privateKey) {
      throw new Error('Issuer not initialized. Call initialize() first.');
    }

    const now = Math.floor(Date.now() / 1000);

    const claims: AgeCredentialClaims = {
      iss: this.issuerDID,
      sub: userDID,
      iat: now,
      exp: now + (365 * 24 * 60 * 60), // Valid 1 year
      birthdate: birthdate.toISOString().split('T')[0], // YYYY-MM-DD
      type: 'AgeCredential',
    };

    // Create JWT with JOSE
    const jwt = await new SignJWT(claims as any)
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .setIssuedAt(now)
      .setExpirationTime(claims.exp)
      .setIssuer(claims.iss)
      .setSubject(claims.sub)
      .sign(this.privateKey);

    // Export public key for verification
    const issuerPublicKey = await exportJWK(this.publicKey!);

    return {
      jwt,
      issuerPublicKey,
      claims,
    };
  }

  /**
   * Get issuer's public key in JWK format
   */
  async getPublicKeyJWK(): Promise<JWK> {
    if (!this.publicKey) {
      throw new Error('Issuer not initialized. Call initialize() first.');
    }
    return exportJWK(this.publicKey);
  }

  /**
   * Get issuer DID
   */
  getDID(): string {
    return this.issuerDID;
  }

  /**
   * Verify a credential (for testing purposes)
   */
  async verifyCredential(jwt: string): Promise<AgeCredentialClaims> {
    if (!this.publicKey) {
      throw new Error('Issuer not initialized. Call initialize() first.');
    }

    const { payload } = await jwtVerify(jwt, this.publicKey, {
      issuer: this.issuerDID,
    });

    // Validate that payload contains required fields
    if (!payload.birthdate || !payload.type) {
      throw new Error('Invalid credential: missing required fields');
    }

    return payload as unknown as AgeCredentialClaims;
  }
}

/**
 * Compute age proof (isOver18) from birthdate without revealing exact date
 *
 * This is a ZK-predicate helper that proves age without disclosing birthdate.
 * In production, this would be computed client-side and only the boolean result
 * would be shared with the verifier.
 *
 * @param birthdate - User's birth date
 * @param requiredAge - Minimum age required (e.g., 18)
 * @returns true if user is at least requiredAge years old
 */
export function computeAgeProof(birthdate: Date, requiredAge: number): boolean {
  const today = new Date();
  const age = today.getFullYear() - birthdate.getFullYear();
  const monthDiff = today.getMonth() - birthdate.getMonth();
  const dayDiff = today.getDate() - birthdate.getDate();

  // Adjust for birthday not yet occurred this year
  if (monthDiff < 0 || (monthDiff === 0 && dayDiff < 0)) {
    return age - 1 >= requiredAge;
  }

  return age >= requiredAge;
}

/**
 * Extract birthdate from credential claims
 *
 * Helper function for testing. In production, this would only be done
 * client-side when the user needs to compute age proofs.
 *
 * @param claims - Credential claims
 * @returns Birthdate as Date object
 */
export function extractBirthdate(claims: AgeCredentialClaims): Date {
  return new Date(claims.birthdate);
}

/**
 * Create a presentation that selectively discloses age without birthdate
 *
 * This creates a proof that the user is over a certain age without
 * revealing the exact birthdate. In SD-JWT, this would be done by
 * not including the birthdate disclosure.
 *
 * @param credential - Issued credential
 * @param requiredAge - Age to prove (e.g., 18)
 * @returns Age proof presentation
 */
export interface AgeProofPresentation {
  /** JWT token (birthdate claim is in JWT but can be validated without revealing) */
  jwt: string;
  /** Computed age proof (boolean) */
  isOverAge: boolean;
  /** Required age */
  requiredAge: number;
  /** Subject DID */
  sub: string;
}

export function createAgeProofPresentation(
  credential: IssuedCredential,
  requiredAge: number
): AgeProofPresentation {
  const birthdate = extractBirthdate(credential.claims);
  const isOverAge = computeAgeProof(birthdate, requiredAge);

  return {
    jwt: credential.jwt,
    isOverAge,
    requiredAge,
    sub: credential.claims.sub,
  };
}
