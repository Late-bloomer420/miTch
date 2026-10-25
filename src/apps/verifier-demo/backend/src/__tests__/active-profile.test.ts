import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { buildSDJWTPresentation, SCENARIO_VCT, validateSDJWTPresentation } from '@askmi/oid4vp';
import {
  buildCNFClaim,
  createKeyBindingJWT,
  issueSDJWTVC,
  trustListResolver,
} from '@askmi/shared-crypto';
import { ASKMI_DEMO } from '@askmi/shared-types';
import { app, setIssuerKeyResolver } from '../app';

describe('active numeric-age profile', () => {
  let issuer: CryptoKeyPair;
  let holder: CryptoKeyPair;
  beforeAll(async () => {
    const keys = () =>
      crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    issuer = await keys();
    holder = await keys();
    trustListResolver.setFetch(
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'test',
          version: '1',
          validUntil: '2030-01-01T00:00:00Z',
          issuers: [ASKMI_DEMO.issuerUri],
          verifiers: [ASKMI_DEMO.verifierDid],
        }),
      })
    );
    trustListResolver.clearCache();
  });
  beforeEach(async () => {
    setIssuerKeyResolver(async () => issuer.publicKey);
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'profile').expect(200);
  });
  async function body(
    claims: Record<string, unknown>,
    vct = SCENARIO_VCT['liquor-store'],
    audience?: string
  ) {
    const {
      body: { authRequest },
    } = await request(app)
      .get('/authorize?scenario=liquor-store')
      .set('X-AskMI-Session-Id', 'profile')
      .expect(200);
    const { presentationSubmission } = await buildSDJWTPresentation({
      request: authRequest,
      issuerPrivateKey: issuer.privateKey,
      holderKeyPair: holder,
      claims: { age: 24 },
      vct,
      issuerDid: ASKMI_DEMO.issuerUri,
    });
    // Sign exactly the supplied claims, including excess claims; the demo builder filters them.
    const jwt = await issueSDJWTVC(
      {
        iss: ASKMI_DEMO.issuerUri,
        vct,
        cnf: await buildCNFClaim(holder.publicKey),
        iat: Math.floor(Date.now() / 1000),
        ...claims,
      },
      issuer.privateKey
    );
    const kb = await createKeyBindingJWT(
      {
        aud: audience ?? authRequest.client_id,
        nonce: authRequest.nonce,
        sdJwtWithDisclosures: `${jwt}~`,
      },
      holder.privateKey
    );
    if (claims.age === 12) {
      const cryptographic = await validateSDJWTPresentation({
        vpTokenString: `${jwt}~${kb}`,
        presentationSubmission,
        request: authRequest,
        issuerPublicKey: issuer.publicKey,
        checkTrust: true,
        checkRevocation: true,
      });
      expect(cryptographic.ok).toBe(true);
      expect(cryptographic.disclosedClaims?.age).toBe(12);
    }
    return {
      vp_token: `${jwt}~${kb}`,
      presentation_submission: presentationSubmission,
      state: authRequest.state,
    };
  }
  function submit(payload: object) {
    return request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', 'profile').send(payload);
  }
  it.each([{ age: 12 }, { age: '24' }, {}, { age: true }, { age: 24, name: 'Private Name' }])(
    'rejects signed claims outside the accepted policy: %j',
    async (claims) => {
      const payload = await body(claims);
      await submit(payload).expect(403);
      await submit(payload).expect(403);
      expect(
        (await request(app).get('/status').set('X-AskMI-Session-Id', 'profile')).body.status
      ).toBe('FAILED');
    }
  );
  it('rejects a valid signature over the wrong credential type', async () => {
    await submit(await body({ age: 24 }, 'https://example.org/unrelated')).expect(403);
  });
  it('rejects a holder-signed response for another audience', async () => {
    await submit(await body({ age: 24 }, undefined, 'did:web:other.example')).expect(403);
  });
  it('consumes malformed attempts before allowing a retry', async () => {
    const payload = await body({ age: 24 });
    await submit({ ...payload, vp_token: 123 }).expect(400);
    await submit(payload).expect(403);
  });
  it('consumes the attempt when the resolver throws', async () => {
    const payload = await body({ age: 24 });
    setIssuerKeyResolver(async () => {
      throw new Error('private upstream details');
    });
    const response = await submit(payload).expect(500);
    expect(JSON.stringify(response.body)).not.toContain('private upstream details');
    setIssuerKeyResolver(async () => issuer.publicKey);
    await submit(payload).expect(403);
  });
  it('rejects a submission for another definition', async () => {
    const payload = await body({ age: 24 });
    payload.presentation_submission.definition_id = 'other';
    await submit(payload).expect(403);
  });
  it('returns eligibility without returning or retaining the numeric age', async () => {
    const response = await submit(await body({ age: 24 })).expect(200);
    expect(response.body.result).toEqual({ eligible: true });
    expect(response.body.disclosedClaims).toBeNull();
    const status = await request(app).get('/status').set('X-AskMI-Session-Id', 'profile');
    expect(status.body.disclosedClaims).toBeNull();
    expect(status.body.result).toEqual({ eligible: true });
  });
  it.each(['/wallet-present', '/present'])(
    'does not allow %s to satisfy an active authorization',
    async (route) => {
      const payload = await body({ age: 24 });
      await request(app)
        .post(route)
        .set('X-AskMI-Session-Id', 'profile')
        .send({ scenarioId: 'liquor-store' })
        .expect(403);
      await submit(payload).expect(200);
      await request(app)
        .post(route)
        .set('X-AskMI-Session-Id', 'profile')
        .send({ scenarioId: 'liquor-store' })
        .expect(403);
    }
  );
});
