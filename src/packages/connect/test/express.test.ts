import { ASKMI_SCENARIO_VCT } from '@askmi/shared-types';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { askmiConnectExpressRouter } from '../src/express/router';
import { createAskMIConnect } from '../src/core/verifier';
import type { PresentationValidator } from '../src/core/types';

/** VP token with a decodable issuer segment so the trust gate is exercised. */
function vpWithIss(iss: string): string {
  const payload = btoa(JSON.stringify({ iss, vct: ASKMI_SCENARIO_VCT['liquor-store'] }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `header.${payload}.sig~kb`;
}

function makeApp(validator: PresentationValidator) {
  const connect = createAskMIConnect({
    verifierDid: 'did:askmi:verifier',
    audienceBaseUrl: 'https://rp.example',
    walletBaseUrl: 'https://wallet.example',
    issuerKeyResolver: async () => ({}) as CryptoKey,
    presentationValidator: validator,
  });
  const app = express();
  app.use(express.json());
  app.use(askmiConnectExpressRouter(connect));
  return app;
}

async function createSessionId(app: express.Express): Promise<string> {
  const res = await request(app).post('/askmi/connect/sessions').send({
    policyId: 'age-liquor-store-v1',
  });
  expect(res.status).toBe(201);
  return res.body.sessionId as string;
}

describe('POST /askmi/connect/sessions', () => {
  it('returns 201 with the contract body including handoff', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const res = await request(app).post('/askmi/connect/sessions').send({
      policyId: 'age-liquor-store-v1',
    });
    expect(res.status).toBe(201);
    expect(res.body.status).toBe('pending');
    expect(res.body.sessionId).toMatch(/^askmi_sess_/);
    expect(res.body.policy).toEqual({ id: 'age-liquor-store-v1', version: 1 });
    expect(res.body.handoff.method).toBe('browser-redirect-or-qr');
    expect(res.body.handoff.presentationEndpoint).toContain(
      `/askmi/connect/sessions/${res.body.sessionId}/presentation`
    );
  });

  it('returns 400 for an unknown policy', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const res = await request(app).post('/askmi/connect/sessions').send({ policyId: 'nope' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('UNKNOWN_POLICY');
  });

  it('does not honor caller-supplied verifierDid/nonce/audience/claims', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const res = await request(app)
      .post('/askmi/connect/sessions')
      .send({
        policyId: 'age-liquor-store-v1',
        verifierDid: 'did:askmi:attacker',
        nonce: 'evil',
        requestedClaims: ['name', 'address'],
        audience: 'https://evil.example',
      });
    expect(res.status).toBe(201);
    expect(res.body.handoff.presentationEndpoint).not.toContain('evil.example');
  });
});

describe('POST .../opened', () => {
  it('returns 204 on a pending session and 404 on unknown', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const sessionId = await createSessionId(app);
    expect(
      (await request(app).post(`/askmi/connect/sessions/${sessionId}/opened`).send({})).status
    ).toBe(204);
    expect(
      (await request(app).post('/askmi/connect/sessions/askmi_sess_missing/opened').send({})).status
    ).toBe(404);
  });
});

describe('POST .../presentation', () => {
  it('returns 200 with minimal result/provenance on success', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const sessionId = await createSessionId(app);
    const res = await request(app)
      .post(`/askmi/connect/sessions/${sessionId}/presentation`)
      .send({
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {
          definition_id: 'askmi-connect',
          descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
        },
        state: sessionId,
      });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('verified');
    expect(res.body.result).toEqual({ eligible: true });
    expect(res.body.verification.cryptographic).toBe('passed');
    expect(res.body.provenance.claimsShared).toEqual(['age']);
  });

  it('maps stable error codes to the ADOPT-1.1 HTTP failure table', async () => {
    const app = makeApp(async () => ({ ok: false, errors: ['Signature verification failed'] }));
    const sessionId = await createSessionId(app);
    const res = await request(app)
      .post(`/askmi/connect/sessions/${sessionId}/presentation`)
      .send({
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {
          definition_id: 'askmi-connect',
          descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
        },
        state: sessionId,
      });
    expect(res.status).toBe(403);
    expect(res.body.status).toBe('failed');
    expect(res.body.error.code).toBe('SIGNATURE_INVALID');
    expect(JSON.stringify(res.body)).not.toContain('Signature verification failed'); // no raw text
  });

  it('returns 400 for a simulated /wallet-present style body', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const sessionId = await createSessionId(app);
    const res = await request(app)
      .post(`/askmi/connect/sessions/${sessionId}/presentation`)
      .send({ scenarioId: 'liquor-store' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('SIMULATED_ROUTE_REJECTED');
  });

  it('returns 404 for an unknown session', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const res = await request(app)
      .post('/askmi/connect/sessions/askmi_sess_missing/presentation')
      .send({
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {
          definition_id: 'askmi-connect',
          descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
        },
      });
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('UNKNOWN_SESSION');
  });

  it('returns 409 (replay) for a second presentation of a verified session', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const sessionId = await createSessionId(app);
    const body = {
      vp_token: vpWithIss('did:askmi:issuer'),
      presentation_submission: {
        definition_id: 'askmi-connect',
        descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
      },
      state: sessionId,
    };
    const first = await request(app)
      .post(`/askmi/connect/sessions/${sessionId}/presentation`)
      .send(body);
    expect(first.status).toBe(200);
    const second = await request(app)
      .post(`/askmi/connect/sessions/${sessionId}/presentation`)
      .send(body);
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('REPLAY_DETECTED');
  });
});

describe('GET /askmi/connect/sessions/:sessionId', () => {
  it('returns the minimal status and never raw credential content', async () => {
    const app = makeApp(async () => ({
      ok: true,
      disclosedClaims: { age: 24 },
      errors: [],
    }));
    const sessionId = await createSessionId(app);
    await request(app)
      .post(`/askmi/connect/sessions/${sessionId}/presentation`)
      .send({
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {
          definition_id: 'askmi-connect',
          descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
        },
        state: sessionId,
      });
    const res = await request(app).get(`/askmi/connect/sessions/${sessionId}`);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('verified');
    expect(res.body.result).toEqual({ eligible: true });
    expect(res.body.provenance.claimsShared).toEqual(['age']);
    const serialized = JSON.stringify(res.body);
    expect(serialized).not.toContain('Zoe'); // no claim values
    expect(serialized).not.toContain('vp_token'); // no credential bytes
    expect(serialized).not.toContain('a~b');
  });

  it('returns 404 for an unknown session without leaking nearby-id existence', async () => {
    const app = makeApp(async () => ({ ok: true, disclosedClaims: { age: 24 }, errors: [] }));
    const sessionId = await createSessionId(app);
    const res = await request(app).get(`/askmi/connect/sessions/${sessionId}x`);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('UNKNOWN_SESSION');
  });
});
