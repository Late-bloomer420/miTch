import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app, ready } from './index'; // export `app` (Express) and a `ready` promise for issuer key init if not already exported
import { validateSDJWTVC, extractCNFPublicKey } from '@askmi/shared-crypto';

async function holderJwk() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { pub: await crypto.subtle.exportKey('jwk', kp.publicKey) };
}

describe('issuer-mock /credential issues vc+sd-jwt', () => {
  it('rejects a request without a holder proof (fail-closed)', async () => {
    await ready;
    const res = await request(app).post('/credential').send({ credential_definition: { type: ['AgeCredential'] } });
    expect(res.status).toBe(400);
  });
  it('issues a vc+sd-jwt bound to the supplied holder key', async () => {
    await ready;
    const { pub } = await holderJwk();
    const res = await request(app).post('/credential').send({ proof: { jwk: pub }, credential_definition: { type: ['AgeCredential'] } });
    expect(res.status).toBe(200);
    expect(res.body.format).toBe('vc+sd-jwt');
    const issuerJwt = res.body.credential.split('~')[0];
    // issuer public key from the mock's jwks
    const jwks = await request(app).get('/.well-known/jwks.json');
    const issuerPub = await crypto.subtle.importKey('jwk', jwks.body.keys[0], { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const v = await validateSDJWTVC(issuerJwt, issuerPub);
    expect(v.ok).toBe(true);
    const cnf = await extractCNFPublicKey(v.payload!);
    expect(cnf).not.toBeNull();
  });
});
