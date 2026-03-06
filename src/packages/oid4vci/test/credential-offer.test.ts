/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * E-02 — OID4VCI Expanded Tests
 *
 * Covers: createOffer structure, issueCredential (all paths),
 * input validation edge cases, policy checks, audit log structure.
 */

import { describe, it, expect, vi } from 'vitest';
import { OID4VCIIssuer } from '../src/index';
import type { CredentialRequest } from '../src/types';

const MOCK_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const MOCK_KEY: JsonWebKey = { kty: 'OKP', crv: 'Ed25519', x: 'mock', d: 'mock' };

function makeIssuer() {
  return new OID4VCIIssuer(MOCK_DID, MOCK_KEY);
}

function validRequest(overrides: Partial<CredentialRequest> = {}): CredentialRequest {
  return {
    credential_type: 'IdentityCredential',
    subject_did: 'did:key:z6MkXXXtest',
    claims: {
      name: 'Alice',
      birthDate: '1995-07-04',
      residency: 'DE',
    },
    nonce: 'nonce-12345678',
    ...overrides,
  };
}

// ── createOffer ────────────────────────────────────────────────────────────────

describe('OID4VCIIssuer.createOffer()', () => {
  it('returns valid JSON string', async () => {
    const issuer = makeIssuer();
    const offer = await issuer.createOffer('IdentityCredential');
    expect(() => JSON.parse(offer)).not.toThrow();
  });

  it('offer contains credential_issuer matching constructor DID', async () => {
    const issuer = makeIssuer();
    const offer = JSON.parse(await issuer.createOffer('IdentityCredential'));
    expect(offer.credential_issuer).toBe(MOCK_DID);
  });

  it('offer contains the requested credential_configuration_ids', async () => {
    const issuer = makeIssuer();
    const offer = JSON.parse(await issuer.createOffer('IdentityCredential'));
    expect(offer.credential_configuration_ids).toContain('IdentityCredential');
  });

  it('offer contains authorization_code grant with issuer_state', async () => {
    const issuer = makeIssuer();
    const offer = JSON.parse(await issuer.createOffer('IdentityCredential'));
    expect(offer.grants).toHaveProperty('authorization_code');
    expect(offer.grants.authorization_code.issuer_state).toBeTruthy();
  });

  it('issuer_state has stateless_nonce_ prefix (PoC timestamp-based)', async () => {
    const issuer = makeIssuer();
    const offer = JSON.parse(await issuer.createOffer('IdentityCredential'));
    expect(offer.grants.authorization_code.issuer_state).toMatch(/^stateless_nonce_\d+$/);
  });
});

// ── issueCredential — Happy Path ───────────────────────────────────────────────

describe('OID4VCIIssuer.issueCredential() — happy path', () => {
  it('returns a credential string', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    expect(typeof res.credential).toBe('string');
    expect(res.credential.length).toBeGreaterThan(0);
  });

  it('credential JSON contains issuer DID', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    const cred = JSON.parse(res.credential);
    expect(cred.issuer).toBe(MOCK_DID);
  });

  it('credential subject.id equals subject_did from request', async () => {
    const issuer = makeIssuer();
    const req = validRequest({ subject_did: 'did:key:z6MkSubject' });
    const res = await issuer.issueCredential(req);
    const cred = JSON.parse(res.credential);
    expect(cred.credentialSubject.id).toBe('did:key:z6MkSubject');
  });

  it('credential subject contains all requested claims', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    const cred = JSON.parse(res.credential);
    expect(cred.credentialSubject.name).toBe('Alice');
    expect(cred.credentialSubject.birthDate).toBe('1995-07-04');
    expect(cred.credentialSubject.residency).toBe('DE');
  });

  it('credential has @context with W3C credentials URL', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    const cred = JSON.parse(res.credential);
    expect(cred['@context']).toContain('https://www.w3.org/2018/credentials/v1');
  });

  it('credential type includes IdentityCredential', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    const cred = JSON.parse(res.credential);
    expect(cred.type).toContain('IdentityCredential');
    expect(cred.type).toContain('VerifiableCredential');
  });

  it('response includes fresh c_nonce (UUID format)', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    expect(res.c_nonce).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('c_nonce_expires_in is a positive number', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest());
    expect(typeof res.c_nonce_expires_in).toBe('number');
    expect(res.c_nonce_expires_in).toBeGreaterThan(0);
  });

  it('successive calls produce different c_nonce values', async () => {
    const issuer = makeIssuer();
    const r1 = await issuer.issueCredential(validRequest());
    const r2 = await issuer.issueCredential(validRequest());
    expect(r1.c_nonce).not.toBe(r2.c_nonce);
  });
});

// ── issueCredential — Input Validation ────────────────────────────────────────

describe('OID4VCIIssuer.issueCredential() — input validation', () => {
  const issuer = makeIssuer();

  it('rejects null input', async () => {
    await expect(issuer.issueCredential(null)).rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects empty object', async () => {
    await expect(issuer.issueCredential({})).rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects wrong credential_type', async () => {
    await expect(issuer.issueCredential({ ...validRequest(), credential_type: 'EvilCred' as any }))
      .rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects subject_did not starting with "did:"', async () => {
    await expect(issuer.issueCredential({ ...validRequest(), subject_did: 'not-a-did' }))
      .rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects missing name claim', async () => {
    await expect(issuer.issueCredential({
      ...validRequest(),
      claims: { birthDate: '1995-07-04', residency: 'DE' } as any
    })).rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects invalid birthDate format', async () => {
    await expect(issuer.issueCredential({
      ...validRequest(),
      claims: { ...validRequest().claims, birthDate: '04-07-1995' }
    })).rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects residency code longer than 2 chars', async () => {
    await expect(issuer.issueCredential({
      ...validRequest(),
      claims: { ...validRequest().claims, residency: 'DEU' }
    })).rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects short nonce (< 8 chars)', async () => {
    await expect(issuer.issueCredential({ ...validRequest(), nonce: 'short' }))
      .rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });

  it('rejects missing nonce entirely', async () => {
    const { nonce: _nonce, ...noNonce } = validRequest();
    await expect(issuer.issueCredential(noNonce)).rejects.toThrow(/FAIL_INPUT_ARBITRATION/);
  });
});

// ── Policy Checks ─────────────────────────────────────────────────────────────

describe('OID4VCIIssuer.issueCredential() — policy', () => {
  it('rejects blocked subject DID containing "did:evil"', async () => {
    const issuer = makeIssuer();
    await expect(issuer.issueCredential(validRequest({ subject_did: 'did:evil:xyz' })))
      .rejects.toThrow(/FAIL_POLICY/);
  });

  it('accepts legitimate did:web subject DID', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest({ subject_did: 'did:web:example.com' }));
    expect(res.credential).toBeTruthy();
  });

  it('accepts did:peer subject DID', async () => {
    const issuer = makeIssuer();
    const res = await issuer.issueCredential(validRequest({ subject_did: 'did:peer:0z6Mk123' }));
    expect(res.credential).toBeTruthy();
  });
});

// ── Audit Logging (side effects) ──────────────────────────────────────────────

describe('OID4VCIIssuer — audit logging', () => {
  it('emits AUDIT log on successful issuance', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const issuer = makeIssuer();
    await issuer.issueCredential(validRequest());
    const auditCall = consoleSpy.mock.calls.find(args =>
      typeof args[0] === 'string' && args[0].includes('[AUDIT]')
    );
    expect(auditCall).toBeDefined();
    consoleSpy.mockRestore();
  });

  it('audit log entry contains subject DID (not PII values)', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const issuer = makeIssuer();
    await issuer.issueCredential(validRequest({ subject_did: 'did:key:z6MkAuditCheck' }));
    const auditRaw = consoleSpy.mock.calls
      .map(args => String(args[0]))
      .find(s => s.includes('[AUDIT]'))!;
    const entry = JSON.parse(auditRaw.replace('[AUDIT] ', ''));
    expect(entry.details.subject).toBe('did:key:z6MkAuditCheck');
    consoleSpy.mockRestore();
  });

  it('audit log does NOT contain raw claim values (data minimization)', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const issuer = makeIssuer();
    await issuer.issueCredential(validRequest({ claims: { name: 'SensitiveName', birthDate: '1990-01-01', residency: 'DE' } }));
    const allLogs = consoleSpy.mock.calls.map(args => String(args[0])).join(' ');
    // Raw PII values must not appear in audit output
    expect(allLogs).not.toContain('SensitiveName');
    consoleSpy.mockRestore();
  });
});
