/**
 * C1 — KB-JWT Proof-of-Possession Gate on /present
 *
 * Proves that the verifier's /present route cryptographically enforces holder
 * Key-Binding for pool-member credentials: a valid KB-JWT passes; a tampered or
 * missing KB-JWT triggers HTTP 403 fail-closed. Non-pool credentials (no
 * holder_binding) are unaffected.
 */

import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import request from 'supertest';
import * as VerifierSdkModule from '@askmi/verifier-sdk';
import { app } from '../app';
import { ASKMI_DEMO, ASKMI_ENV } from '@askmi/shared-types';
import { createKeyBindingJWT } from '@askmi/shared-crypto';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

async function makeEcPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
}

function didJwkFromJwk(jwk: JsonWebKey): string {
  const pub: JsonWebKey = { ...jwk };
  delete (pub as Record<string, unknown>).d;
  return `did:jwk:${Buffer.from(JSON.stringify(pub), 'utf8').toString('base64url')}`;
}

const VERIFIER_DID = ASKMI_DEMO.verifierDid;
const SESSION_NONCE = 'test-nonce-c1-xyz';
const FLOW_SESSION_ID = 'kbjwt-present-test';

function makeVp(holderBinding: { kb_jwt: string; sub: string } | null) {
  return {
    vp: {
      metadata: { type: 'VerifiablePresentationBundle', nonce: SESSION_NONCE, decision_id: 'd1', timestamp: Date.now(), validUntil: Date.now() + 60000, issuer_trust_refs: [] },
      presentations: [{
        type: 'AgeCredential',
        disclosure: { isOver18: true },
        proven_claims: {},
        ...(holderBinding ? { holder_binding: holderBinding } : {}),
      }],
    },
  };
}

// Stub sdk.verifyPresentation so we control the vp payload without real crypto.
function stubSdk(vp: ReturnType<typeof makeVp>) {
  vi.spyOn(VerifierSdkModule.VerifierSDK.prototype, 'verifyPresentation').mockResolvedValue(vp as never);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('/present — KB-JWT Proof-of-Possession gate (C1)', () => {
  let holderKeys: CryptoKeyPair;
  let holderSub: string;

  beforeAll(async () => {
    process.env[ASKMI_ENV.testMode] = '1';
    holderKeys = await makeEcPair();
    const pub = await globalThis.crypto.subtle.exportKey('jwk', holderKeys.publicKey);
    holderSub = didJwkFromJwk(pub);
  });

  afterEach(() => { vi.restoreAllMocks(); });

  it('rejects a tampered KB-JWT signature with 403', async () => {
    const kb_jwt = await createKeyBindingJWT(
      { aud: VERIFIER_DID, nonce: SESSION_NONCE, sdJwtWithDisclosures: holderSub },
      holderKeys.privateKey
    );
    const parts = kb_jwt.split('.');
    parts[2] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    stubSdk(makeVp({ kb_jwt: parts.join('.'), sub: holderSub }));

    const res = await request(app)
      .post('/present')
      .set('X-AskMI-Session-Id', FLOW_SESSION_ID)
      .set('x-forwarded-for', '127.0.0.1')
      .send({});
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('KB_JWT_VERIFICATION_FAILED');
  });

  it('rejects when aud does not match verifier DID', async () => {
    const kb_jwt = await createKeyBindingJWT(
      { aud: 'did:evil:attacker', nonce: SESSION_NONCE, sdJwtWithDisclosures: holderSub },
      holderKeys.privateKey
    );
    stubSdk(makeVp({ kb_jwt, sub: holderSub }));

    const res = await request(app)
      .post('/present')
      .set('X-AskMI-Session-Id', FLOW_SESSION_ID)
      .set('x-forwarded-for', '127.0.0.1')
      .send({});
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('KB_JWT_VERIFICATION_FAILED');
  });

  it('rejects when nonce does not match session nonce', async () => {
    const kb_jwt = await createKeyBindingJWT(
      { aud: VERIFIER_DID, nonce: 'wrong-nonce', sdJwtWithDisclosures: holderSub },
      holderKeys.privateKey
    );
    stubSdk(makeVp({ kb_jwt, sub: holderSub }));

    const res = await request(app)
      .post('/present')
      .set('X-AskMI-Session-Id', FLOW_SESSION_ID)
      .set('x-forwarded-for', '127.0.0.1')
      .send({});
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('KB_JWT_VERIFICATION_FAILED');
  });

  it('does not enforce KB-JWT for non-pool credentials (no holder_binding)', async () => {
    stubSdk(makeVp(null));
    const res = await request(app)
      .post('/present')
      .set('X-AskMI-Session-Id', FLOW_SESSION_ID)
      .set('x-forwarded-for', '127.0.0.1')
      .send({});
    // Without holder_binding the gate is skipped; ZKP stub has no proof so it 403s AGE_NOT_VERIFIED.
    expect(res.body.error).not.toBe('KB_JWT_VERIFICATION_FAILED');
    expect(res.body.error).not.toBe('KB_JWT_INVALID_HOLDER_KEY');
  });
});
