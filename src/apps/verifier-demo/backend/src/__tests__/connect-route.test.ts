import { beforeAll, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import {
  buildCNFClaim,
  issueSDJWTVC,
  createKeyBindingJWT,
  trustListResolver,
  createSDJWTDisclosures,
  buildSdJwtPresentation,
} from '@askmi/shared-crypto';
import { ASKMI_DEMO, ASKMI_SCENARIO_VCT } from '@askmi/shared-types';
import { app, setIssuerKeyResolver } from '../app';

describe('integrated Connect numeric-age route', () => {
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
        }),
      })
    );
    trustListResolver.clearCache();
    setIssuerKeyResolver(async (iss) => (iss === ASKMI_DEMO.issuerUri ? issuer.publicKey : null));
  });
  async function start() {
    const created = await request(app)
      .post('/askmi/connect/sessions')
      .send({ policyId: 'age-liquor-store-v1' })
      .expect(201);
    const id = created.body.sessionId as string;
    const handoff = new URL(created.body.handoff.url);
    const requestUri = new URL(handoff.searchParams.get('request_uri')!);
    expect(requestUri.pathname).toBe(`/askmi/connect/sessions/${id}/request`);
    const authorized = await request(app).get(requestUri.pathname).expect(200);
    return { id, auth: authorized.body.authRequest };
  }
  async function signed(
    auth: Awaited<ReturnType<typeof start>>['auth'],
    claims: Record<string, unknown>,
    vct = ASKMI_SCENARIO_VCT['liquor-store']
  ) {
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
      { aud: auth.client_id, nonce: auth.nonce, sdJwtWithDisclosures: `${jwt}~` },
      holder.privateKey
    );
    return {
      vp_token: `${jwt}~${kb}`,
      state: auth.state,
      presentation_submission: {
        id: 'presentation',
        definition_id: auth.presentation_definition.id,
        descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
      },
    };
  }
  function submit(id: string, body: object) {
    return request(app).post(`/askmi/connect/sessions/${id}/presentation`).send(body);
  }
  it('hands off the stored request and returns only eligibility once', async () => {
    const { id, auth } = await start();
    const payload = await signed(auth, { age: 24 });
    const response = await submit(id, payload).expect(200);
    expect(response.body.result).toEqual({ eligible: true });
    expect(JSON.stringify(response.body)).not.toContain('"age":24');
    const status = await request(app).get(`/askmi/connect/sessions/${id}`).expect(200);
    expect(status.body.result).toEqual({ eligible: true });
    expect(status.body).not.toHaveProperty('authorizationRequest');
    await submit(id, payload).expect(409);
    await request(app).get(`/askmi/connect/sessions/${id}/request`).expect(409);
  });
  it.each([{ age: 12 }, {}, { age: '24' }, { age: 24, name: 'Private Name' }])(
    'rejects signed policy/profile violation %j',
    async (claims) => {
      const { id, auth } = await start();
      const payload = await signed(auth, claims);
      await submit(id, payload).expect(403);
      await submit(id, payload).expect(409);
    }
  );
  it('rejects the wrong signed credential type', async () => {
    const { id, auth } = await start();
    await submit(id, await signed(auth, { age: 24 }, 'https://example.org/other')).expect(403);
  });
  it('requires state and the exact descriptor mapping', async () => {
    const a = await start();
    const b = await start();
    await submit(a.id, { ...(await signed(a.auth, { age: 24 })), state: undefined }).expect(403);
    const payload = await signed(b.auth, { age: 24 });
    payload.presentation_submission.descriptor_map = [];
    await submit(b.id, payload).expect(403);
  });
  it('does not let a legacy simulated route satisfy Connect', async () => {
    const { id } = await start();
    await request(app)
      .post('/wallet-present')
      .set('X-AskMI-Session-Id', id)
      .send({ scenarioId: 'liquor-store' });
    const status = await request(app).get(`/askmi/connect/sessions/${id}`).expect(200);
    expect(status.body.status).toBe('pending');
  });
  it('rejects transfer to another session even with substituted state', async () => {
    const a = await start();
    const b = await start();
    const payload = await signed(a.auth, { age: 24 });
    await submit(b.id, { ...payload, state: b.id }).expect(403);
    await submit(a.id, payload).expect(200);
  });
  it('rejects a signed wrong audience', async () => {
    const { id, auth } = await start();
    await submit(
      id,
      await signed({ ...auth, client_id: 'did:other:verifier' }, { age: 24 })
    ).expect(403);
  });
  it('rejects an untrusted issuer and an invalid holder signature', async () => {
    const a = await start();
    const b = await start();
    await submit(a.id, await signed(a.auth, { age: 24, iss: 'did:other:issuer' })).expect(403);
    const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    await submit(
      b.id,
      await signed(b.auth, { age: 24, cnf: await buildCNFClaim(other.publicKey) })
    ).expect(403);
  });
  it('reserves concurrent real submissions exactly once', async () => {
    const { id, auth } = await start();
    const payload = await signed(auth, { age: 24 });
    const responses = await Promise.all([submit(id, payload), submit(id, payload)]);
    expect(responses.map((r) => r.status).sort()).toEqual([200, 409]);
  });
  it('expires the stored authorization and rejects further use', async () => {
    const { id, auth } = await start();
    const payload = await signed(auth, { age: 24 });
    const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 300_001);
    try {
      await submit(id, payload).expect(410);
      await request(app).get(`/askmi/connect/sessions/${id}/request`).expect(410);
    } finally {
      clock.mockRestore();
    }
  });
  it('persists a resolver failure and hides its diagnostics', async () => {
    const { id, auth } = await start();
    const payload = await signed(auth, { age: 24 });
    setIssuerKeyResolver(async () => {
      throw new Error('private upstream diagnostic');
    });
    try {
      const response = await submit(id, payload).expect(503);
      expect(response.body.error.code).toBe('ISSUER_RESOLUTION_FAILED');
      expect(JSON.stringify(response.body)).not.toContain('private');
      await submit(id, payload).expect(409);
      expect((await request(app).get(`/askmi/connect/sessions/${id}`)).body.status).toBe('failed');
    } finally {
      setIssuerKeyResolver(async (iss) => (iss === ASKMI_DEMO.issuerUri ? issuer.publicKey : null));
    }
  });
  it('rejects a signed excess prototype property', async () => {
    const { id, auth } = await start();
    await submit(
      id,
      await signed(auth, JSON.parse('{"age":24,"__proto__":{"name":"Private"}}'))
    ).expect(403);
  });
  it('accepts the wallet selective-disclosure format and rejects disclosure of an extra name', async () => {
    const { _sd, disclosures } = await createSDJWTDisclosures({ age: 24, name: 'Private Name' });
    const jwt = await issueSDJWTVC(
      {
        iss: ASKMI_DEMO.issuerUri,
        vct: ASKMI_SCENARIO_VCT['liquor-store'],
        cnf: await buildCNFClaim(holder.publicKey),
        iat: Math.floor(Date.now() / 1000),
        _sd,
      },
      issuer.privateKey
    );
    const stored = `${jwt}~${disclosures.join('~')}~`;
    for (const names of [['age'], ['age', 'name']]) {
      const { id, auth } = await start();
      const payload = await signed(auth, { age: 24 });
      const { vpToken } = await buildSdJwtPresentation(stored, names, holder.privateKey, {
        aud: auth.client_id,
        nonce: auth.nonce,
      });
      await submit(id, { ...payload, vp_token: vpToken }).expect(names.length === 1 ? 200 : 403);
    }
  });
});
