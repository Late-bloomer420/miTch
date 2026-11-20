import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app, ready } from './index';
import { SDJWTStatusResolver } from '@askmi/shared-crypto';

// API-05: the mock issuer serves a signed status list that a live-mode verifier accepts.

async function issuerKey(): Promise<CryptoKey> {
  const jwks = await request(app).get('/.well-known/jwks.json');
  return crypto.subtle.importKey('jwk', jwks.body.keys[0], { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}

/** Route the resolver's fetch to the in-process Express app. */
const appFetch = (async (_url: string, init?: RequestInit) => {
  const accept = (init?.headers as Record<string, string> | undefined)?.Accept ?? '';
  const res = await request(app).get('/status-list/1').set('Accept', accept);
  return new Response(res.text, { status: res.status, headers: { 'content-type': res.type } });
}) as typeof fetch;

describe('issuer-mock /status-list/1', () => {
  it('serves a signed VC-JWT when asked and the live resolver verifies it', async () => {
    await ready;
    const key = await issuerKey();
    const resolver = new SDJWTStatusResolver({
      fetchFn: appFetch,
      statusListMode: 'live',
      resolveStatusListKey: async (iss, kid) =>
        iss === 'did:web:localhost%3A3005' && kid === 'key-1' ? key : null,
    });
    const revoked = await resolver.checkStatus({ status_list: { idx: 42, uri: 'http://localhost:3005/status-list/1' } });
    expect(revoked).toMatchObject({ decision: 'DENY', revoked: true });
    const valid = await resolver.checkStatus({ status_list: { idx: 7, uri: 'http://localhost:3005/status-list/1' } });
    expect(valid).toMatchObject({ decision: 'ALLOW', revoked: false });
  });

  it('a live resolver without the issuer key rejects the list (fail-closed)', async () => {
    await ready;
    const resolver = new SDJWTStatusResolver({
      fetchFn: appFetch,
      statusListMode: 'live',
      resolveStatusListKey: async () => null,
    });
    const r = await resolver.checkStatus({ status_list: { idx: 7, uri: 'http://localhost:3005/status-list/1' } });
    expect(r.decision).toBe('DENY');
  });

  it('keeps plain JSON for clients that do not ask for vc+jwt', async () => {
    await ready;
    const res = await request(app).get('/status-list/1');
    expect(res.body.credentialSubject.type).toBe('StatusList2021');
  });
});
