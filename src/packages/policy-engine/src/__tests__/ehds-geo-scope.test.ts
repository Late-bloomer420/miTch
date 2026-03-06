/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * T-A4: GeoScope enforcement tests
 * Tests geographic scope checks in policy engine evaluation and helper functions.
 */
import { describe, it, expect } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import { extractCountryFromDid, isAllowedByGeoScope } from '../geo-scope';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';

// ─── Helper function unit tests ───

describe('extractCountryFromDid', () => {
  it('extracts 2-letter country from did:XX:name format', () => {
    expect(extractCountryFromDid('did:de:hospital-berlin')).toBe('DE');
    expect(extractCountryFromDid('did:us:hospital-new-york')).toBe('US');
    expect(extractCountryFromDid('did:jp:research-tokyo')).toBe('JP');
  });

  it('returns null for non-standard DID formats', () => {
    expect(extractCountryFromDid('did:example:foo')).toBeNull(); // 7 chars, not 2
    expect(extractCountryFromDid('something')).toBeNull();
    expect(extractCountryFromDid('did:x:foo')).toBeNull(); // 1 char
  });

  it('uppercases the country code', () => {
    expect(extractCountryFromDid('did:de:test')).toBe('DE');
  });
});

describe('isAllowedByGeoScope', () => {
  it('allows any country for global scope', () => {
    expect(isAllowedByGeoScope('global', 'US')).toBe(true);
    expect(isAllowedByGeoScope('global', 'CN')).toBe(true);
  });

  it('allows null country (fail-open)', () => {
    expect(isAllowedByGeoScope('eu-only', null)).toBe(true);
  });

  it('eu-only allows EU/EEA countries', () => {
    expect(isAllowedByGeoScope('eu-only', 'DE')).toBe(true);
    expect(isAllowedByGeoScope('eu-only', 'NO')).toBe(true); // EEA
    expect(isAllowedByGeoScope('eu-only', 'US')).toBe(false);
    expect(isAllowedByGeoScope('eu-only', 'JP')).toBe(false);
  });

  it('eu-plus-adequacy allows EU/EEA + adequacy countries', () => {
    expect(isAllowedByGeoScope('eu-plus-adequacy', 'DE')).toBe(true);
    expect(isAllowedByGeoScope('eu-plus-adequacy', 'JP')).toBe(true);
    expect(isAllowedByGeoScope('eu-plus-adequacy', 'UK')).toBe(true);
    expect(isAllowedByGeoScope('eu-plus-adequacy', 'CN')).toBe(false);
    expect(isAllowedByGeoScope('eu-plus-adequacy', 'US')).toBe(false);
  });

  it('unknown scope allows everything', () => {
    expect(isAllowedByGeoScope('unknown-scope', 'CN')).toBe(true);
  });
});

// ─── Integration tests with PolicyEngine ───

const HEALTH_CREDENTIAL: StoredCredentialMetadata = {
  id: 'vc-health-001',
  issuer: 'did:example:ehealth-authority',
  type: ['VerifiableCredential', 'PatientSummary'],
  issuedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
  claims: ['bloodGroup', 'allergies'],
};

function makePolicy(geoScope?: string): PolicyManifest {
  const rule: any = {
    id: 'rule-geo-test',
    verifierPattern: 'did:*:*',
    allowedClaims: ['bloodGroup', 'allergies'],
    provenClaims: [],
    requiresTrustedIssuer: true,
    maxCredentialAgeDays: 365,
    requiresUserConsent: true,
    priority: 50,
  };
  if (geoScope) rule.geoScope = geoScope;
  return {
    version: '1.2',
    globalSettings: { blockUnknownVerifiers: false },
    trustedIssuers: [
      { did: 'did:example:ehealth-authority', name: 'eHealth Authority', credentialTypes: ['PatientSummary', 'VerifiableCredential'] },
    ],
    rules: [rule],
  };
}

function makeRequest(verifierId: string): VerifierRequest {
  return {
    verifierId,
    origin: 'https://example.com',
    requirements: [{
      credentialType: 'PatientSummary',
      requestedClaims: ['bloodGroup', 'allergies'],
      requestedProvenClaims: [],
    }],
  };
}

describe('PolicyEngine geoScope enforcement', () => {
  const engine = new PolicyEngine();
  const ctx: EvaluationContext = { timestamp: Date.now(), userDID: 'did:example:wallet-user' };

  it('eu-only: DE hospital → PROMPT (allowed)', async () => {
    const result = await engine.evaluate(makeRequest('did:de:hospital-berlin'), ctx, [HEALTH_CREDENTIAL], makePolicy('eu-only'));
    expect(result.verdict).not.toBe('DENY');
    expect(result.reasonCodes).not.toContain(ReasonCode.GEO_SCOPE_VIOLATION);
  });

  it('eu-only: US hospital → DENY + GEO_SCOPE_VIOLATION', async () => {
    const result = await engine.evaluate(makeRequest('did:us:hospital-new-york'), ctx, [HEALTH_CREDENTIAL], makePolicy('eu-only'));
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(ReasonCode.GEO_SCOPE_VIOLATION);
  });

  it('eu-plus-adequacy: JP research → PROMPT (adequacy)', async () => {
    const result = await engine.evaluate(makeRequest('did:jp:research-tokyo'), ctx, [HEALTH_CREDENTIAL], makePolicy('eu-plus-adequacy'));
    expect(result.verdict).not.toBe('DENY');
    expect(result.reasonCodes).not.toContain(ReasonCode.GEO_SCOPE_VIOLATION);
  });

  it('eu-plus-adequacy: CN hospital → DENY', async () => {
    const result = await engine.evaluate(makeRequest('did:cn:hospital-beijing'), ctx, [HEALTH_CREDENTIAL], makePolicy('eu-plus-adequacy'));
    expect(result.verdict).toBe('DENY');
    expect(result.reasonCodes).toContain(ReasonCode.GEO_SCOPE_VIOLATION);
  });

  it('no geoScope set → allows any country', async () => {
    const result = await engine.evaluate(makeRequest('did:cn:hospital-beijing'), ctx, [HEALTH_CREDENTIAL], makePolicy());
    expect(result.verdict).not.toBe('DENY');
  });

  it('global geoScope → allows any country', async () => {
    const result = await engine.evaluate(makeRequest('did:cn:hospital-beijing'), ctx, [HEALTH_CREDENTIAL], makePolicy('global'));
    expect(result.verdict).not.toBe('DENY');
  });
});
