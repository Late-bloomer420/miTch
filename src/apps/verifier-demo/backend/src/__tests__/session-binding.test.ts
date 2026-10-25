import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { buildSDJWTPresentation, SCENARIO_VCT } from '@askmi/oid4vp';
import { trustListResolver } from '@askmi/shared-crypto';
import { ASKMI_DEMO } from '@askmi/shared-types';
import { app, setIssuerKeyResolver } from '../app';

describe('OID4VP authorization ownership', () => {
  let issuer: CryptoKeyPair;
  let holder: CryptoKeyPair;

  beforeAll(async () => {
    issuer = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    holder = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
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
    for (const id of ['alice', 'bob'])
      await request(app).post('/reset').set('X-AskMI-Session-Id', id).expect(200);
  });
  afterEach(() => vi.restoreAllMocks());

  async function authorize(id: string) {
    const response = await request(app)
      .get('/authorize?scenario=liquor-store')
      .set('X-AskMI-Session-Id', id)
      .expect(200);
    return response.body.authRequest;
  }
  async function presentation(auth: Awaited<ReturnType<typeof authorize>>) {
    const built = await buildSDJWTPresentation({
      request: auth,
      issuerPrivateKey: issuer.privateKey,
      holderKeyPair: holder,
      claims: { age: 24 },
      vct: SCENARIO_VCT['liquor-store'],
      issuerDid: ASKMI_DEMO.issuerUri,
      revoked: false,
    });
    return {
      vp_token: built.vpTokenString,
      presentation_submission: built.presentationSubmission,
      state: auth.state,
    };
  }
  function present(id: string, body: Awaited<ReturnType<typeof presentation>>) {
    return request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', id).send(body);
  }

  it('rejects a response redirected to a session without an authorization', async () => {
    const body = await presentation(await authorize('alice'));
    await present('bob', body).expect(403);
    expect((await request(app).get('/status').set('X-AskMI-Session-Id', 'bob')).body.status).toBe(
      'WAITING'
    );
    await present('alice', body).expect(200);
  });

  it('checks the signed nonce even when the attacker substitutes the destination state', async () => {
    const body = await presentation(await authorize('alice'));
    const bob = await authorize('bob');
    await present('bob', { ...body, state: bob.state }).expect(403);
    await present('alice', body).expect(200);
  });

  it.each([undefined, 'wrong-state'])('rejects mismatched state %s', async (state) => {
    const body = await presentation(await authorize('alice'));
    await present('alice', { ...body, state }).expect(403);
  });

  it('accepts a valid response once and rejects its replay', async () => {
    const body = await presentation(await authorize('alice'));
    await present('alice', body).expect(200);
    await present('alice', body).expect(403);
  });

  it('invalidates a pending response on reset', async () => {
    const body = await presentation(await authorize('alice'));
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'alice').expect(200);
    await present('alice', body).expect(403);
  });

  it('invalidates the previous request when a new authorization is issued', async () => {
    const body = await presentation(await authorize('alice'));
    await authorize('alice');
    await present('alice', body).expect(403);
  });

  it('rejects an expired authorization even if the session is still being polled', async () => {
    const body = await presentation(await authorize('alice'));
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + 5 * 60 * 1000 + 1);
    await present('alice', body).expect(403);
  });

  it('does not restore verified status if reset occurs while issuer resolution is pending', async () => {
    const body = await presentation(await authorize('alice'));
    let release!: (key: CryptoKey) => void;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    setIssuerKeyResolver(() => {
      entered();
      return new Promise((resolve) => {
        release = resolve;
      });
    });
    const response = present('alice', body).then((result) => result);
    await started;
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'alice').expect(200);
    release(issuer.publicKey);
    expect((await response).status).toBe(403);
    expect((await request(app).get('/status').set('X-AskMI-Session-Id', 'alice')).body.status).toBe(
      'WAITING'
    );
  });

  it('accepts only one of two concurrent submissions', async () => {
    const body = await presentation(await authorize('alice'));
    const responses = await Promise.all([present('alice', body), present('alice', body)]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 403]);
  });
});
