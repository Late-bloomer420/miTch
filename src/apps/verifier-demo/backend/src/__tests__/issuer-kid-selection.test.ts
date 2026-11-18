import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import {
  buildCNFClaim,
  createKeyBindingJWT,
  issueSDJWTVC,
  trustListResolver,
} from '@askmi/shared-crypto';
import { ASKMI_DEMO, ASKMI_SCENARIO_VCT } from '@askmi/shared-types';
import { app, defaultResolveIssuerKey, setIssuerKeyResolver } from '../app';
import { protectedHeaderKid, selectIssuerJwk } from '../issuer-jwks';

// Synthetic keys, JWKS and trust list. Covers issuer-key selection only (#240 `kid`
// item); not trust-list signature, status-list signature or external issuer evidence.

const newKeys = () =>
  crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]) as Promise<CryptoKeyPair>;
const publicJwk = async (k: CryptoKeyPair, extra: Record<string, unknown> = {}) => ({
  ...(await crypto.subtle.exportKey('jwk', k.publicKey)),
  use: 'sig',
  alg: 'ES256',
  ...extra,
});

describe('selectIssuerJwk', () => {
  let a: JsonWebKey & { kid: string };
  let b: JsonWebKey & { kid: string };
  beforeAll(async () => {
    a = (await publicJwk(await newKeys(), { kid: 'key-a' })) as typeof a;
    b = (await publicJwk(await newKeys(), { kid: 'key-b' })) as typeof b;
  });

  it('selects the key whose kid matches the header', () => {
    expect(selectIssuerJwk([a, b], 'key-b')).toBe(b);
  });
  it('denies an unknown kid', () => {
    expect(selectIssuerJwk([a, b], 'key-c')).toBeNull();
  });
  it('denies a duplicated kid', () => {
    expect(selectIssuerJwk([a, { ...b, kid: 'key-a' }], 'key-a')).toBeNull();
  });
  it('accepts a missing kid only when exactly one candidate exists', () => {
    expect(selectIssuerJwk([a], undefined)).toBe(a);
    expect(selectIssuerJwk([a, b], undefined)).toBeNull();
  });
  it.each<[string, Record<string, unknown>]>([
    ['private key material', { d: 'secret' }],
    ['another curve', { crv: 'P-384' }],
    ['an RSA key', { kty: 'RSA' }],
    ['an encryption key', { use: 'enc' }],
    ['another algorithm', { alg: 'ES384' }],
    ['missing coordinates', { x: undefined }],
  ])('never selects %s', (_label, change) => {
    expect(selectIssuerJwk([{ ...a, ...change }], 'key-a')).toBeNull();
    expect(selectIssuerJwk([{ ...a, ...change }], undefined)).toBeNull();
  });
  it('denies a non-array key set', () => {
    expect(selectIssuerJwk({ keys: [a] }, 'key-a')).toBeNull();
    expect(selectIssuerJwk(undefined, undefined)).toBeNull();
  });
  it('reads kid only from a string protected-header field', () => {
    const jws = (header: unknown) =>
      `${Buffer.from(JSON.stringify(header)).toString('base64url')}.e30.sig`;
    expect(protectedHeaderKid(jws({ alg: 'ES256', kid: 'key-a' }))).toBe('key-a');
    expect(protectedHeaderKid(jws({ alg: 'ES256', kid: 7 }))).toBeUndefined();
    expect(protectedHeaderKid('not-a-jws')).toBeUndefined();
  });
});

describe('active route resolves the issuer key by kid', () => {
  const SESSION = 'kid-selection';
  let keyA: CryptoKeyPair;
  let keyB: CryptoKeyPair;
  let holder: CryptoKeyPair;
  let jwks: unknown[];

  beforeAll(async () => {
    keyA = await newKeys();
    keyB = await newKeys();
    holder = await newKeys();
    jwks = [await publicJwk(keyA, { kid: 'key-a' }), await publicJwk(keyB, { kid: 'key-b' })];
  });

  beforeEach(async () => {
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
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () => ({ ok: true, json: async () => ({ keys: jwks }) }))
    );
    setIssuerKeyResolver(defaultResolveIssuerKey);
    await request(app).post('/reset').set('X-AskMI-Session-Id', SESSION).expect(200);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function present(signWith: CryptoKeyPair, kid: string | undefined) {
    const {
      body: { authRequest },
    } = await request(app)
      .get('/authorize?scenario=liquor-store')
      .set('X-AskMI-Session-Id', SESSION)
      .expect(200);
    const jwt = await issueSDJWTVC(
      {
        iss: ASKMI_DEMO.issuerUri,
        vct: ASKMI_SCENARIO_VCT['liquor-store'],
        cnf: await buildCNFClaim(holder.publicKey),
        iat: Math.floor(Date.now() / 1000),
        age: 24,
      },
      signWith.privateKey,
      kid ? { kid } : undefined
    );
    const kb = await createKeyBindingJWT(
      { aud: authRequest.client_id, nonce: authRequest.nonce, sdJwtWithDisclosures: `${jwt}~` },
      holder.privateKey
    );
    return request(app)
      .post('/oid4vp-present')
      .set('X-AskMI-Session-Id', SESSION)
      .send({
        vp_token: `${jwt}~${kb}`,
        presentation_submission: {
          id: 'sub',
          definition_id: 'pd-age-verification',
          descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
        },
        state: authRequest.state,
      });
  }

  it('accepts a credential signed by the second JWKS key when its kid names it', async () => {
    expect((await present(keyB, 'key-b')).status).toBe(200);
  });

  it('denies a credential whose kid names a different key than the signer', async () => {
    expect((await present(keyB, 'key-a')).status).toBe(403);
  });

  it('denies an unknown kid', async () => {
    expect((await present(keyA, 'key-unknown')).status).toBe(403);
  });

  it('denies a credential without kid when the JWKS is ambiguous', async () => {
    expect((await present(keyA, undefined)).status).toBe(403);
  });
});
