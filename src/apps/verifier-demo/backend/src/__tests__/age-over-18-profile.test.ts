import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { SCENARIO_VCT } from '@askmi/oid4vp';
import {
  buildCNFClaim,
  createKeyBindingJWT,
  createSDJWTDisclosures,
  issueSDJWTVC,
  trustListResolver,
} from '@askmi/shared-crypto';
import { ASKMI_DEMO } from '@askmi/shared-types';
import { app, setIssuerKeyResolver } from '../app';
import { AGE_OVER_18_EXPLORATION } from '../active-profile';

// Profile C: non-official, issuer-signed flat age_over_18 boolean. Synthetic keys and a
// synthetic trust list only; this is not EUDI, ZK or unlinkability evidence.
const SESSION = 'age-over-18';
const PROFILE = AGE_OVER_18_EXPLORATION.profileId;

type Keys = CryptoKeyPair;
const newKeys = () =>
  crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]) as Promise<Keys>;

describe('age_over_18 exploration profile (Profile C)', () => {
  let issuer: Keys;
  let holder: Keys;

  beforeAll(async () => {
    issuer = await newKeys();
    holder = await newKeys();
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
    await request(app).post('/reset').set('X-AskMI-Session-Id', SESSION).expect(200);
  });

  async function authorize(scenario = AGE_OVER_18_EXPLORATION.scenarioId) {
    const res = await request(app)
      .get(`/authorize?scenario=${scenario}`)
      .set('X-AskMI-Session-Id', SESSION)
      .expect(200);
    return res.body.authRequest;
  }

  interface Opts {
    /** Selectively disclosed claims (issuer-signed via _sd digests). */
    disclosed?: Record<string, unknown>;
    vct?: string;
    issuerKey?: CryptoKey;
    audience?: string;
    nonce?: string;
    definitionId?: string;
    descriptorId?: string;
    /** Issuer-signed `exp` (seconds since epoch); omitted when undefined. */
    exp?: number;
  }

  async function presentation(authRequest: Record<string, any>, opts: Opts = {}) {
    const disclosed = opts.disclosed ?? { age_over_18: true };
    const { disclosures, _sd: sdDigests } = await createSDJWTDisclosures(disclosed);
    const jwt = await issueSDJWTVC(
      {
        iss: ASKMI_DEMO.issuerUri,
        vct: opts.vct ?? AGE_OVER_18_EXPLORATION.vct,
        cnf: await buildCNFClaim(holder.publicKey),
        iat: Math.floor(Date.now() / 1000),
        ...(opts.exp !== undefined ? { exp: opts.exp } : {}),
        _sd: sdDigests,
        _sd_alg: 'sha-256',
      },
      opts.issuerKey ?? issuer.privateKey
    );
    const sdJwtWithDisclosures = [jwt, ...disclosures].join('~') + '~';
    const kb = await createKeyBindingJWT(
      {
        aud: opts.audience ?? authRequest.client_id,
        nonce: opts.nonce ?? authRequest.nonce,
        sdJwtWithDisclosures,
      },
      holder.privateKey
    );
    return {
      vp_token: `${sdJwtWithDisclosures}${kb}`,
      presentation_submission: {
        id: 'sub-1',
        definition_id: opts.definitionId ?? authRequest.presentation_definition.id,
        descriptor_map: [
          {
            id: opts.descriptorId ?? AGE_OVER_18_EXPLORATION.descriptorId,
            format: 'sd-jwt',
            path: '$',
          },
        ],
      },
      state: authRequest.state,
    };
  }

  const submit = (payload: object) =>
    request(app).post('/oid4vp-present').set('X-AskMI-Session-Id', SESSION).send(payload);
  const status = () => request(app).get('/status').set('X-AskMI-Session-Id', SESSION);

  it('requests the boolean claim, not numeric age', async () => {
    const authRequest = await authorize();
    expect(authRequest.presentation_definition.id).toBe(AGE_OVER_18_EXPLORATION.definitionId);
    const paths = authRequest.presentation_definition.input_descriptors.flatMap((d: any) =>
      d.constraints.fields.flatMap((f: any) => f.path)
    );
    expect(paths).toEqual(['$.age_over_18']);
  });

  it('returns only eligibility and the profile id to the application', async () => {
    const authRequest = await authorize();
    const response = await submit(await presentation(authRequest)).expect(200);
    expect(response.body.result).toEqual({ eligible: true, profile: PROFILE });
    expect(response.body.disclosedClaims).toBeNull();
    const s = await status();
    expect(s.body.status).toBe('VERIFIED');
    expect(s.body.result).toEqual({ eligible: true, profile: PROFILE });
    expect(s.body.disclosedClaims).toBeNull();
  });

  it.each<[string, Record<string, unknown>]>([
    ['false', { age_over_18: false }],
    ['string "true"', { age_over_18: 'true' }],
    ['number 1', { age_over_18: 1 }],
    ['null', { age_over_18: null }],
    ['numeric age instead of the boolean', { age: 24 }],
    ['an additional claim', { age_over_18: true, birthdate: '2000-01-01' }],
    ['no claim at all', {}],
  ])('rejects %s and consumes the attempt', async (_label, disclosed) => {
    const authRequest = await authorize();
    const payload = await presentation(authRequest, { disclosed });
    await submit(payload).expect(403);
    expect((await status()).body.status).toBe('FAILED');
    expect((await status()).body.result).toBeNull();
    // One-shot: even a now-valid presentation cannot reuse the consumed authorization.
    await submit(await presentation(authRequest)).expect(403);
  });

  it('rejects the numeric-age credential type in a boolean session', async () => {
    const authRequest = await authorize();
    await submit(await presentation(authRequest, { vct: SCENARIO_VCT['liquor-store'] })).expect(
      403
    );
  });

  it('rejects a boolean credential presented to a numeric-age session', async () => {
    const authRequest = await authorize('liquor-store');
    await submit(await presentation(authRequest, { descriptorId: 'age-credential' })).expect(403);
  });

  it('rejects a submission naming the other profile definition', async () => {
    const authRequest = await authorize();
    await submit(await presentation(authRequest, { definitionId: 'pd-age-verification' })).expect(
      403
    );
  });

  it('rejects a credential signed by a key other than the resolved issuer key', async () => {
    const other = await newKeys();
    const authRequest = await authorize();
    await submit(await presentation(authRequest, { issuerKey: other.privateKey })).expect(403);
  });

  it('rejects when the issuer key cannot be resolved', async () => {
    setIssuerKeyResolver(async () => null);
    const authRequest = await authorize();
    await submit(await presentation(authRequest)).expect(403);
  });

  it('rejects a holder binding for another audience', async () => {
    const authRequest = await authorize();
    await submit(await presentation(authRequest, { audience: 'did:web:other.example' })).expect(
      403
    );
  });

  it('rejects a holder binding over another nonce', async () => {
    const authRequest = await authorize();
    await submit(await presentation(authRequest, { nonce: 'not-the-request-nonce' })).expect(403);
  });

  it('rejects an expired credential and consumes the attempt', async () => {
    const authRequest = await authorize();
    const now = Math.floor(Date.now() / 1000);
    const response = await submit(await presentation(authRequest, { exp: now - 60 })).expect(403);
    expect(JSON.stringify(response.body)).not.toContain('age_over_18":true');
    expect((await status()).body.status).toBe('FAILED');
    expect((await status()).body.result).toBeNull();
    await submit(await presentation(authRequest, { exp: now + 3600 })).expect(403);
  });

  it('accepts a credential whose exp is still in the future', async () => {
    const authRequest = await authorize();
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const response = await submit(await presentation(authRequest, { exp })).expect(200);
    expect(response.body.result).toEqual({ eligible: true, profile: PROFILE });
  });

  // Characterization, not a security PASS: `exp` is optional in validateSDJWTVC, so a
  // credential without it never expires. Kept visible until a lifetime rule exists (#293).
  it('currently accepts a credential without exp (documented gap)', async () => {
    const authRequest = await authorize();
    await submit(await presentation(authRequest)).expect(200);
  });

  it('rejects replay of an accepted presentation', async () => {
    const authRequest = await authorize();
    const payload = await presentation(authRequest);
    await submit(payload).expect(200);
    await submit(payload).expect(403);
  });

  it('rejects a presentation bound to an earlier authorization', async () => {
    const first = await authorize();
    const stale = await presentation(first);
    await authorize();
    await submit(stale).expect(403);
  });
});
