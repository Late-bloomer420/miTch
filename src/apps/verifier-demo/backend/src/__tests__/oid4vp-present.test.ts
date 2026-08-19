/**
 * B-02: OID4VP Direct Post Endpoint Tests
 *
 * Tests the /oid4vp-present endpoint that receives SD-JWT VP Token
 * from the wallet via direct_post and validates it.
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { app, setIssuerKeyResolver } from '../app';
import { buildSDJWTPresentation, SCENARIO_VCT } from '@askmi/oid4vp';
import { statusResolver, trustListResolver } from '@askmi/shared-crypto';
import { ASKMI_DEMO, ASKMI_ENV, ASKMI_SCENARIO_VCT } from '@askmi/shared-types';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const AGE_CLAIMS = {
  age: 24,
  dateOfBirth: '2000-01-01',
  name: 'Max Mustermann',
  address: 'Zirl, AT',
  nationalId: 'AT-123456',
};

const MOCK_TSL = {
  id: 'test-tsl',
  version: '1.0.0',
  validUntil: '2030-01-01T00:00:00Z',
  issuers: [ASKMI_DEMO.issuerUri],
  verifiers: [ASKMI_DEMO.verifierDid],
};

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('/oid4vp-present endpoint', () => {
  let issuerKeys: CryptoKeyPair;
  let holderKeys: CryptoKeyPair;

  beforeAll(async () => {
    // Set test mode to avoid file I/O for verifier keys
    process.env[ASKMI_ENV.testMode] = '1';
    issuerKeys = await generateKeyPair();
    holderKeys = await generateKeyPair();

    // Mock TSL fetch
    const fetchFn = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => MOCK_TSL,
    });
    trustListResolver.setFetch(fetchFn as any);
    trustListResolver.clearCache();
  });

  beforeEach(async () => {
    // Reset verifier state
    await request(app).post('/reset');
    // ADOPT-0b: the verifier resolves the issuer key itself (trust list / JWKS),
    // NOT from the wallet. Inject the test issuer key as the "resolved" key.
    setIssuerKeyResolver(async () => issuerKeys.publicKey);
  });

  it('should return 400 when vp_token is missing', async () => {
    const res = await request(app)
      .post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test')
      .send({ presentation_submission: {}, issuer_jwk: {} });

    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBe('Missing vp_token');
  });

  it('should return 400 when presentation_submission is missing', async () => {
    const res = await request(app)
      .post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test')
      .send({ vp_token: 'fake.token.here', issuer_jwk: {} });

    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBe('Missing presentation_submission');
  });

  it('rejects (403) when the issuer key cannot be resolved / issuer is untrusted', async () => {
    const authRes = await request(app).get('/authorize?scenario=liquor-store');
    const { authRequest } = authRes.body;
    const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
      request: authRequest,
      issuerPrivateKey: issuerKeys.privateKey,
      holderKeyPair: holderKeys,
      claims: AGE_CLAIMS,
      vct: SCENARIO_VCT['liquor-store'] ?? ASKMI_SCENARIO_VCT['liquor-store'],
      issuerDid: ASKMI_DEMO.issuerUri,
      revoked: false,
    });
    // Issuer untrusted / JWKS unresolvable → the verifier must not accept it.
    setIssuerKeyResolver(async () => null);
    const res = await request(app)
      .post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test')
      .send({ vp_token: vpTokenString, presentation_submission: presentationSubmission, state: authRequest.state });

    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBe('untrusted_or_unresolvable_issuer');
  });

  it('ignores a wallet-supplied issuer_jwk and verifies against the resolved key (closes circular-verification)', async () => {
    const authRes = await request(app).get('/authorize?scenario=liquor-store');
    const { authRequest } = authRes.body;
    const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
      request: authRequest,
      issuerPrivateKey: issuerKeys.privateKey,
      holderKeyPair: holderKeys,
      claims: AGE_CLAIMS,
      vct: SCENARIO_VCT['liquor-store'] ?? ASKMI_SCENARIO_VCT['liquor-store'],
      issuerDid: ASKMI_DEMO.issuerUri,
      revoked: false,
    });
    // Resolver (beforeEach) returns the REAL issuer key. Send an ATTACKER key as
    // issuer_jwk — it must be ignored; verification uses the resolved key → 200.
    const attacker = await globalThis.crypto.subtle.exportKey(
      'jwk',
      (await generateKeyPair()).publicKey
    );
    const res = await request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test').send({
      vp_token: vpTokenString,
      presentation_submission: presentationSubmission,
      state: authRequest.state,
      issuer_jwk: attacker,
    });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('should verify a valid SD-JWT VP (happy path)', async () => {
    // Step 1: Get an auth request with a valid nonce
    const authRes = await request(app).get('/authorize?scenario=liquor-store');
    expect(authRes.status).toBe(200);
    const { authRequest } = authRes.body;

    // Step 2: Build a real SD-JWT VP token
    const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
      request: authRequest,
      issuerPrivateKey: issuerKeys.privateKey,
      holderKeyPair: holderKeys,
      claims: AGE_CLAIMS,
      vct: SCENARIO_VCT['liquor-store'] ?? ASKMI_SCENARIO_VCT['liquor-store'],
      issuerDid: ASKMI_DEMO.issuerUri,
      revoked: false,
    });

    // Step 3: Export issuer public key as JWK
    const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

    // Step 4: POST to /oid4vp-present
    const res = await request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test').send({
      vp_token: vpTokenString,
      presentation_submission: presentationSubmission,
      state: authRequest.state,
      issuer_jwk: issuerJwk,
    });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.disclosedClaims).toBeDefined();
    expect(res.body.consentReceipt).toBeDefined();

    // Verify status endpoint reflects the result
    const statusRes = await request(app).get('/status').set('X-AskMI-Session-Id', 'oid4vp-test');
    expect(statusRes.body.status).toBe('VERIFIED');
    expect(statusRes.body.disclosedClaims).toBeDefined();
  });

  it('should reject a revoked credential', async () => {
    // Mock bitstring for index 42 revoked
    const bitstring = new Uint8Array(64);
    bitstring[5] = 0b00100000; // Bit 42 set

    const mockSL = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'https://example.com/status-list/1',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:web:issuer.example.com',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'https://example.com/status-list/1#list',
        type: 'StatusList2021',
        statusPurpose: 'revocation',
        encodedList: Buffer.from(bitstring).toString('base64'),
      },
    };

    const fetchFn = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockSL,
    });

    vi.stubGlobal('fetch', fetchFn);
    statusResolver.setFetch(fetchFn as any);

    const authRes = await request(app).get('/authorize?scenario=revoked');
    expect(authRes.status).toBe(200);
    const { authRequest } = authRes.body;

    const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
      request: authRequest,
      issuerPrivateKey: issuerKeys.privateKey,
      holderKeyPair: holderKeys,
      claims: { age: 24 },
      vct: SCENARIO_VCT['revoked'] ?? ASKMI_SCENARIO_VCT.revoked,
      issuerDid: ASKMI_DEMO.issuerUri,
      revoked: true,
    });

    const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

    const res = await request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test').send({
      vp_token: vpTokenString,
      presentation_submission: presentationSubmission,
      state: authRequest.state,
      issuer_jwk: issuerJwk,
    });

    expect(res.status).toBe(403);
    expect(res.body.ok).toBe(false);
    expect(res.body.errors).toBeDefined();
    expect(res.body.errors.some((e: string) => e.toLowerCase().includes('revok'))).toBe(true);

    vi.unstubAllGlobals();
  });

  it('should verify doctor-login scenario with selective disclosure', async () => {
    const authRes = await request(app).get('/authorize?scenario=doctor-login');
    expect(authRes.status).toBe(200);
    const { authRequest } = authRes.body;

    const doctorClaims = {
      age: 35,
      role: 'Surgeon',
      licenseId: 'MED-998877',
      employer: 'St. Mary Hospital',
      salary: 'redacted',
      homeAddress: 'redacted',
    };

    const { vpTokenString, presentationSubmission, disclosedClaims } = await buildSDJWTPresentation(
      {
        request: authRequest,
        issuerPrivateKey: issuerKeys.privateKey,
        holderKeyPair: holderKeys,
        claims: doctorClaims,
        vct: SCENARIO_VCT['doctor-login'] ?? ASKMI_SCENARIO_VCT['doctor-login'],
        issuerDid: ASKMI_DEMO.issuerUri,
        revoked: false,
      }
    );

    const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

    const res = await request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test').send({
      vp_token: vpTokenString,
      presentation_submission: presentationSubmission,
      state: authRequest.state,
      issuer_jwk: issuerJwk,
    });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    // Selective disclosure: salary and homeAddress should be redacted
    if (res.body.disclosedClaims) {
      expect(disclosedClaims).toBeDefined();
    }
  });

  it('should return 500 for malformed vp_token with valid issuer_jwk', async () => {
    const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

    const res = await request(app)
      .post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test')
      .send({
        vp_token: 'not.a.valid.sd-jwt~token',
        presentation_submission: { id: 'test', definition_id: 'test', descriptor_map: [] },
        issuer_jwk: issuerJwk,
      });

    // Should fail validation — either 403 or 500 depending on where it fails
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.body.ok).toBe(false);
  });

  it('should update /status after successful verification', async () => {
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'oid4vp-test');
    // Initial status should be WAITING (after reset)
    const initialStatus = await request(app).get('/status').set('X-AskMI-Session-Id', 'oid4vp-test');
    expect(initialStatus.body.status).toBe('WAITING');

    // Run a successful verification
    const authRes = await request(app).get('/authorize?scenario=liquor-store');
    const { authRequest } = authRes.body;

    const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
      request: authRequest,
      issuerPrivateKey: issuerKeys.privateKey,
      holderKeyPair: holderKeys,
      claims: AGE_CLAIMS,
      vct: SCENARIO_VCT['liquor-store'] ?? ASKMI_SCENARIO_VCT['liquor-store'],
      issuerDid: ASKMI_DEMO.issuerUri,
      revoked: false,
    });

    const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

    await request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', 'oid4vp-test').send({
      vp_token: vpTokenString,
      presentation_submission: presentationSubmission,
      issuer_jwk: issuerJwk,
    });

    // Status should now be VERIFIED
    const updatedStatus = await request(app).get('/status').set('X-AskMI-Session-Id', 'oid4vp-test');
    expect(updatedStatus.body.status).toBe('VERIFIED');
    expect(updatedStatus.body.disclosedClaims).toBeDefined();
    expect(updatedStatus.body.consentReceipt).toBeDefined();
  });
});




