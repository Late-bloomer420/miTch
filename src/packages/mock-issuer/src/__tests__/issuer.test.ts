import { describe, it, expect, beforeEach } from 'vitest';
import {
  MockGovernmentIssuer,
  computeAgeProof,
  extractBirthdate,
  createAgeProofPresentation,
} from '../index';

describe('MockGovernmentIssuer', () => {
  let issuer: MockGovernmentIssuer;

  beforeEach(async () => {
    issuer = new MockGovernmentIssuer();
    await issuer.initialize();
  });

  it('should issue age credential with JWT', async () => {
    const birthdate = new Date('1990-05-15');
    const userDID = 'did:example:user123';

    const credential = await issuer.issueAgeCredential(birthdate, userDID);

    expect(credential).toBeDefined();
    expect(credential.jwt).toBeDefined();
    expect(typeof credential.jwt).toBe('string');
    expect(credential.jwt.split('.')).toHaveLength(3); // JWT has 3 parts
    expect(credential.issuerPublicKey).toBeDefined();
    expect(credential.claims.sub).toBe(userDID);
    expect(credential.claims.birthdate).toBe('1990-05-15');
    expect(credential.claims.type).toBe('AgeCredential');
  });

  it('should compute isOver18 predicate correctly', () => {
    const over18 = new Date('1990-01-01');
    const under18 = new Date('2010-01-01');

    expect(computeAgeProof(over18, 18)).toBe(true);
    expect(computeAgeProof(under18, 18)).toBe(false);
  });

  it('should compute isOver21 predicate correctly', () => {
    const over21 = new Date('2000-01-01');
    const under21 = new Date('2006-01-01');

    expect(computeAgeProof(over21, 21)).toBe(true);
    expect(computeAgeProof(under21, 21)).toBe(false);
  });

  it('should handle edge case: birthday today', () => {
    const today = new Date();
    const exactly18Today = new Date(
      today.getFullYear() - 18,
      today.getMonth(),
      today.getDate()
    );

    expect(computeAgeProof(exactly18Today, 18)).toBe(true);
  });

  it('should handle edge case: birthday tomorrow (still 17)', () => {
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const turns18Tomorrow = new Date(
      tomorrow.getFullYear() - 18,
      tomorrow.getMonth(),
      tomorrow.getDate()
    );

    expect(computeAgeProof(turns18Tomorrow, 18)).toBe(false);
  });

  it('should return issuer DID', () => {
    expect(issuer.getDID()).toBe('did:example:government-issuer');
  });

  it('should export public key in JWK format', async () => {
    const jwk = await issuer.getPublicKeyJWK();

    expect(jwk).toBeDefined();
    expect(jwk.kty).toBe('EC'); // Elliptic Curve
    expect(jwk.crv).toBe('P-256'); // ES256 curve
  });

  it('should verify issued credential', async () => {
    const birthdate = new Date('1995-03-20');
    const userDID = 'did:example:alice';

    const credential = await issuer.issueAgeCredential(birthdate, userDID);

    // Verify credential
    const verifiedClaims = await issuer.verifyCredential(credential.jwt);

    expect(verifiedClaims.sub).toBe(userDID);
    expect(verifiedClaims.birthdate).toBe('1995-03-20');
    expect(verifiedClaims.iss).toBe(issuer.getDID());
  });

  it('should extract birthdate from claims', async () => {
    const birthdate = new Date('1988-12-25');
    const userDID = 'did:example:bob';

    const credential = await issuer.issueAgeCredential(birthdate, userDID);
    const extractedDate = extractBirthdate(credential.claims);

    expect(extractedDate.getFullYear()).toBe(1988);
    expect(extractedDate.getMonth()).toBe(11); // December (0-indexed)
    expect(extractedDate.getDate()).toBe(25);
  });

  it('should create age proof presentation without revealing birthdate', async () => {
    const birthdate = new Date('1990-06-15');
    const userDID = 'did:example:charlie';

    const credential = await issuer.issueAgeCredential(birthdate, userDID);
    const presentation = createAgeProofPresentation(credential, 18);

    expect(presentation.isOverAge).toBe(true);
    expect(presentation.requiredAge).toBe(18);
    expect(presentation.sub).toBe(userDID);
    expect(presentation.jwt).toBe(credential.jwt);

    // Verify that birthdate is not directly exposed in presentation
    // (only isOverAge boolean is revealed)
    expect(presentation).not.toHaveProperty('birthdate');
  });

  it('should fail to verify credential with wrong issuer key', async () => {
    const birthdate = new Date('1992-08-10');
    const userDID = 'did:example:dave';

    const credential = await issuer.issueAgeCredential(birthdate, userDID);

    // Create another issuer with different keys
    const maliciousIssuer = new MockGovernmentIssuer('did:example:malicious');
    await maliciousIssuer.initialize();

    // Should fail verification
    await expect(maliciousIssuer.verifyCredential(credential.jwt)).rejects.toThrow();
  });
});

describe('computeAgeProof', () => {
  it('should return true for age >= required', () => {
    const birthdate = new Date('1980-01-01');
    expect(computeAgeProof(birthdate, 18)).toBe(true);
    expect(computeAgeProof(birthdate, 21)).toBe(true);
    expect(computeAgeProof(birthdate, 30)).toBe(true);
  });

  it('should return false for age < required', () => {
    const birthdate = new Date('2010-01-01');
    expect(computeAgeProof(birthdate, 18)).toBe(false);
    expect(computeAgeProof(birthdate, 21)).toBe(false);
  });

  it('should handle different required ages', () => {
    const birthdate = new Date('2000-06-15'); // Person is ~25-26 years old in 2026

    expect(computeAgeProof(birthdate, 16)).toBe(true);
    expect(computeAgeProof(birthdate, 18)).toBe(true);
    expect(computeAgeProof(birthdate, 21)).toBe(true);
    expect(computeAgeProof(birthdate, 25)).toBe(true); // Now 25-26 years old
    expect(computeAgeProof(birthdate, 30)).toBe(false); // Not yet 30
  });
});
