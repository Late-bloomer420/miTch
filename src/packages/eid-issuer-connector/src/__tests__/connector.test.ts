import { describe, it, expect, beforeEach } from 'vitest';
import { EIDIssuerConnector, computeAge, isOver18 } from '../index';
import { importJWK, jwtVerify } from 'jose';
import type { EIDIssuanceRequest } from '../types';

describe('EIDIssuerConnector — Simulator Mode', () => {
  let connector: EIDIssuerConnector;

  beforeEach(async () => {
    connector = new EIDIssuerConnector('simulator', {
      issuerDID: 'did:web:eid-simulator.mitch.local',
    });
    await connector.initialize();
  });

  // ─── Full Issuance Flow ─────────────────────────────────────────────

  it('should issue SD-JWT VC credential via simulated eID flow', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:alice',
      requestedAttributes: ['givenName', 'familyName', 'dateOfBirth'],
      purpose: 'Age verification for online service',
    };

    const response = await connector.requestIssuance(request);

    expect(response.format).toBe('sd-jwt-vc');
    expect(response.issuer).toBe('did:web:eid-simulator.mitch.local');
    expect(response.issuedAt).toBeLessThanOrEqual(Date.now());
    expect(response.expiresAt).toBeGreaterThan(Date.now());

    // SD-JWT structure: <jwt>~<disclosure1>~<disclosure2>~...~
    const parts = response.credential.split('~');
    expect(parts.length).toBeGreaterThan(1); // JWT + at least one disclosure
    expect(parts[0].split('.')).toHaveLength(3); // JWT has 3 parts
  });

  // ─── Credential Verification ────────────────────────────────────────

  it('should verify credential against issuer public key', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:bob',
      requestedAttributes: ['givenName', 'dateOfBirth'],
      purpose: 'Identity verification',
    };

    const response = await connector.requestIssuance(request);
    const result = await connector.verifyCredential(response.credential);

    expect(result.payload.iss).toBe('did:web:eid-simulator.mitch.local');
    expect(result.payload.sub).toBe('did:example:bob');
    expect(result.payload.vct).toBe('urn:eu:europa:ec:eudi:pid:1');
    expect(result.payload._sd_alg).toBe('sha-256');
    expect(result.payload._sd).toBeDefined();
    expect(result.payload._sd!.length).toBeGreaterThan(0);
  });

  it('should verify credential using static method with JWK', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:charlie',
      requestedAttributes: ['givenName', 'familyName'],
      purpose: 'KYC check',
    };

    const response = await connector.requestIssuance(request);
    const publicKeyJwk = connector.getPublicKeyJWK();

    // This is what an external verifier would do
    const result = await EIDIssuerConnector.verifyWithPublicKey(
      response.credential,
      publicKeyJwk,
      'did:web:eid-simulator.mitch.local'
    );

    expect(result.payload.sub).toBe('did:example:charlie');
    expect(result.disclosures.length).toBe(2);
    expect(result.disclosures.map(d => d.name).sort()).toEqual(['familyName', 'givenName']);
  });

  // ─── SD-JWT Disclosures ─────────────────────────────────────────────

  it('should include correct selective disclosures', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:dave',
      requestedAttributes: ['givenName', 'familyName', 'dateOfBirth', 'nationality'],
      purpose: 'Full identity check',
    };

    const response = await connector.requestIssuance(request);
    const result = await connector.verifyCredential(response.credential);

    const disclosureNames = result.disclosures.map(d => d.name).sort();
    expect(disclosureNames).toEqual(['dateOfBirth', 'familyName', 'givenName', 'nationality']);

    const givenName = result.disclosures.find(d => d.name === 'givenName');
    expect(givenName?.value).toBe('Max');

    const dob = result.disclosures.find(d => d.name === 'dateOfBirth');
    expect(dob?.value).toBe('1990-01-15');
  });

  // ─── Age Predicate ──────────────────────────────────────────────────

  it('should include age_over_18 predicate for adult citizen', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:adult',
      requestedAttributes: ['givenName', 'dateOfBirth'],
      purpose: 'Age check',
    };

    const response = await connector.requestIssuance(request, 'default');
    const result = await connector.verifyCredential(response.credential);

    expect(result.isOver18).toBe(true);
    expect(result.payload).toHaveProperty('age_over_18', true);
  });

  it('should include age_over_18 = false for minor citizen', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:minor',
      requestedAttributes: ['givenName', 'dateOfBirth'],
      purpose: 'Age check',
    };

    const response = await connector.requestIssuance(request, 'minor');
    const result = await connector.verifyCredential(response.credential);

    expect(result.isOver18).toBe(false);
    expect(result.payload).toHaveProperty('age_over_18', false);
  });

  // ─── DID Document ───────────────────────────────────────────────────

  it('should publish a valid DID Document with verification key', () => {
    const didDoc = connector.getDIDDocument();

    expect(didDoc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(didDoc.id).toBe('did:web:eid-simulator.mitch.local');
    expect(didDoc.verificationMethod).toHaveLength(1);
    expect(didDoc.verificationMethod[0].type).toBe('JsonWebKey2020');
    expect(didDoc.verificationMethod[0].publicKeyJwk).toBeDefined();
    expect(didDoc.verificationMethod[0].publicKeyJwk.kty).toBe('EC');
    expect(didDoc.verificationMethod[0].publicKeyJwk.crv).toBe('P-256');
    expect(didDoc.assertionMethod).toContain(`${didDoc.id}#key-1`);
  });

  it('should verify credential using key from DID Document', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:verifier-test',
      requestedAttributes: ['givenName'],
      purpose: 'DID Document key test',
    };

    const response = await connector.requestIssuance(request);
    const didDoc = connector.getDIDDocument();
    const jwk = didDoc.verificationMethod[0].publicKeyJwk;

    // Verifier resolves DID Document → extracts key → verifies
    const result = await EIDIssuerConnector.verifyWithPublicKey(
      response.credential,
      jwk as any,
      didDoc.id
    );

    expect(result.payload.sub).toBe('did:example:verifier-test');
  });

  // ─── Invalid Requests ──────────────────────────────────────────────

  it('should reject request with missing userDID', async () => {
    const request = {
      userDID: '',
      requestedAttributes: ['givenName'],
      purpose: 'test',
    } as EIDIssuanceRequest;

    await expect(connector.requestIssuance(request)).rejects.toThrow('Invalid issuance request');
  });

  it('should reject request with empty attributes', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:test',
      requestedAttributes: [],
      purpose: 'test',
    };

    await expect(connector.requestIssuance(request)).rejects.toThrow('Invalid issuance request');
  });

  it('should reject request with missing purpose', async () => {
    const request = {
      userDID: 'did:example:test',
      requestedAttributes: ['givenName'],
      purpose: '',
    } as EIDIssuanceRequest;

    await expect(connector.requestIssuance(request)).rejects.toThrow('Invalid issuance request');
  });

  it('should reject unknown citizen profile', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:test',
      requestedAttributes: ['givenName'],
      purpose: 'test',
    };

    await expect(connector.requestIssuance(request, 'nonexistent')).rejects.toThrow(
      'Unknown citizen profile'
    );
  });

  it('should fail verification with wrong key', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:tamper-test',
      requestedAttributes: ['givenName'],
      purpose: 'test',
    };

    const response = await connector.requestIssuance(request);

    // Create a different connector with different keys
    const otherConnector = new EIDIssuerConnector('simulator');
    await otherConnector.initialize();

    await expect(otherConnector.verifyCredential(response.credential)).rejects.toThrow();
  });

  // ─── Protocol Sessions ─────────────────────────────────────────────

  it('should track protocol session through all states', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:session-test',
      requestedAttributes: ['givenName'],
      purpose: 'Session tracking test',
    };

    await connector.requestIssuance(request);
    const sessions = connector.getAllSessions();

    expect(sessions).toHaveLength(1);
    expect(sessions[0].state).toBe('complete');
    expect(sessions[0].completedAt).toBeDefined();
    expect(sessions[0].citizenData).toBeDefined();
  });

  // ─── Backward Compatibility ─────────────────────────────────────────

  it('should still work in legacy mock mode', async () => {
    const mockConnector = new EIDIssuerConnector('mock');
    await mockConnector.initialize();

    const request: EIDIssuanceRequest = {
      userDID: 'did:example:legacy',
      requestedAttributes: ['givenName', 'familyName', 'dateOfBirth'],
      purpose: 'Legacy test',
    };

    const response = await mockConnector.requestIssuance(request);
    expect(response.format).toBe('jwt');
    expect(response.credential.split('.')).toHaveLength(3);
  });

  it('should throw for unimplemented modes', async () => {
    const ausweisConnector = new EIDIssuerConnector('ausweisapp2');
    await expect(ausweisConnector.initialize()).rejects.toThrow('not yet implemented');
  });
});

// ─── Utility Functions ──────────────────────────────────────────────────────

describe('computeAge', () => {
  it('should compute age correctly for adult', () => {
    const birthdate = new Date('1990-01-15');
    const age = computeAge(birthdate, new Date('2026-03-04'));
    expect(age).toBe(36);
  });

  it('should handle birthday not yet occurred this year', () => {
    const birthdate = new Date('1990-06-15');
    const age = computeAge(birthdate, new Date('2026-03-04'));
    expect(age).toBe(35);
  });

  it('should handle birthday today', () => {
    const today = new Date();
    const birthdate = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
    expect(computeAge(birthdate)).toBe(18);
  });
});

describe('isOver18', () => {
  it('should return true for adults', () => {
    expect(isOver18(new Date('1990-01-01'))).toBe(true);
  });

  it('should return false for minors', () => {
    expect(isOver18(new Date('2012-06-20'))).toBe(false);
  });
});
