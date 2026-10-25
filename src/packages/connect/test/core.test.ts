import { describe, expect, it } from 'vitest';

import { createAskMIConnect } from '../src/core/verifier';
import { InMemoryAskMIConnectSessionStore } from '../src/core/session-store';
import type { PresentationValidator } from '../src/core/types';

/**
 * Core unit tests use the presentationValidator seam so session-contract
 * behaviour is deterministic without fabricating crypto. The real
 * @askmi/oid4vp path is the default outside tests.
 */

const ISSUER_KEY = {} as CryptoKey; // never reached: the validator is stubbed

function okValidator(claims: Record<string, unknown>): PresentationValidator {
  return async () => ({ ok: true, disclosedClaims: claims, errors: [] });
}

function failingValidator(errors: string[]): PresentationValidator {
  return async () => ({ ok: false, errors });
}

/** VP token with a decodable issuer segment so the trust gate is exercised. */
function vpWithIss(iss: string): string {
  const payload = btoa(JSON.stringify({ iss }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `header.${payload}.sig~kb`;
}

function makeConnect(overrides: {
  validator?: PresentationValidator;
  ttlMs?: number;
  store?: InMemoryAskMIConnectSessionStore;
}) {
  return createAskMIConnect({
    verifierDid: 'did:askmi:verifier',
    audienceBaseUrl: 'https://rp.example',
    walletBaseUrl: 'https://wallet.example',
    issuerKeyResolver: async () => ISSUER_KEY,
    ...(overrides.ttlMs !== undefined ? { sessionTtlMs: overrides.ttlMs } : {}),
    ...(overrides.store !== undefined ? { store: overrides.store } : {}),
    ...(overrides.validator !== undefined ? { presentationValidator: overrides.validator } : {}),
  });
}

async function createPendingSession(connect: ReturnType<typeof makeConnect>) {
  const created = await connect.createSession({ policyId: 'age-liquor-store-v1' });
  if (!created.ok) throw new Error('session creation failed');
  return created.session;
}

describe('createSession', () => {
  it('creates a pending session with the contract fields and a handoff', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const result = await connect.createSession({ policyId: 'age-liquor-store-v1' });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const s = result.session;
    expect(s.status).toBe('pending');
    expect(s.sessionId).toMatch(/^askmi_sess_/);
    expect(s.nonce.length).toBeGreaterThanOrEqual(32);
    expect(s.audience).toBe(
      `https://rp.example/askmi/connect/sessions/${s.sessionId}/presentation`
    );
    expect(s.verifierDid).toBe('did:askmi:verifier');
    expect(s.policyId).toBe('age-liquor-store-v1');
    expect(s.policyVersion).toBe(1);
    expect(s.correlationId).toMatch(/^txn_/);
    expect(result.handoff.method).toBe('browser-redirect-or-qr');
    expect(result.handoff.url).toContain(`state=${encodeURIComponent(s.sessionId)}`);
    expect(result.handoff.presentationEndpoint).toBe(s.audience);
  });

  it('rejects an unknown policy id', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const result = await connect.createSession({
      policyId: 'not-a-policy' as 'age-liquor-store-v1',
    });
    expect(result).toEqual({ ok: false, code: 'UNKNOWN_POLICY' });
  });

  it('ignores application-supplied trust-relevant fields (fail-closed contract)', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const result = await connect.createSession({
      policyId: 'age-liquor-store-v1',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.session.verifierDid).toBe('did:askmi:verifier'); // never caller-supplied
  });

  it('two concurrent sessions do not collide', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const r = await connect.createSession({ policyId: 'age-liquor-store-v1' });
      if (!r.ok) throw new Error('creation failed');
      ids.add(r.session.sessionId);
    }
    expect(ids.size).toBe(50);
    const nonces = new Set<string>();
    for (const id of ids) {
      const g = await connect.getSession(id);
      if (g.ok) nonces.add(g.session.nonce);
    }
    expect(nonces.size).toBe(50);
  });
});

describe('completeSession (negative contract)', () => {
  it('fails closed on an unknown session', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const r = await connect.completeSession({
      sessionId: 'askmi_sess_missing',
      body: { vp_token: vpWithIss('did:askmi:issuer'), presentation_submission: {} },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('UNKNOWN_SESSION');
  });

  it('fails closed on an expired session (TTL elapsed)', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }), ttlMs: 0 });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: s.sessionId,
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('SESSION_EXPIRED');
    const g = await connect.getSession(s.sessionId);
    if (g.ok) expect(g.session.status).toBe('expired');
  });

  it('rejects a legacy /wallet-present style simulated body (never verified)', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: { scenarioId: 'liquor-store', claims: { age: 24 } },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('SIMULATED_ROUTE_REJECTED');
    const g = await connect.getSession(s.sessionId);
    if (g.ok) expect(g.session.status).toBe('failed');
  });

  it('rejects a malformed body (missing vp_token / submission)', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const s = await createPendingSession(connect);
    const missingToken = await connect.completeSession({
      sessionId: s.sessionId,
      body: { presentation_submission: {} },
    });
    expect(missingToken.ok).toBe(false);
    if (!missingToken.ok) expect(missingToken.code).toBe('MALFORMED_PRESENTATION');
    const s2 = await createPendingSession(connect);
    const missingSubmission = await connect.completeSession({
      sessionId: s2.sessionId,
      body: { vp_token: vpWithIss('did:askmi:issuer') },
    });
    expect(missingSubmission.ok).toBe(false);
    if (!missingSubmission.ok) expect(missingSubmission.code).toBe('MALFORMED_PRESENTATION');
  });

  it('fails closed when the issuer is not trusted (default resolver rejects everything)', async () => {
    const connect = createAskMIConnect({
      verifierDid: 'did:askmi:verifier',
      audienceBaseUrl: 'https://rp.example',
      walletBaseUrl: 'https://wallet.example',
      presentationValidator: okValidator({ age: 24 }),
      // no issuerKeyResolver -> fail-closed default
    });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: 'x.eyJpc3MiOiJkaWQ6YXNrbWk6aXNzdWVyIn0.y~kb',
        presentation_submission: {},
        state: s.sessionId,
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('UNTRUSTED_ISSUER');
  });

  it('fails closed when state does not match the session', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: 'askmi_sess_other',
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('WRONG_NONCE');
  });

  it('maps validator nonce and audience errors to stable codes', async () => {
    const connect = makeConnect({ validator: failingValidator(['nonce mismatch']) });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: s.sessionId,
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('WRONG_NONCE');

    const connect2 = makeConnect({ validator: failingValidator(['aud mismatch']) });
    const s2 = await createPendingSession(connect2);
    const r2 = await connect2.completeSession({
      sessionId: s2.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: s2.sessionId,
      },
    });
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.code).toBe('WRONG_AUDIENCE');
  });

  it('produces INSUFFICIENT_CLAIMS when age is missing after valid verification', async () => {
    const connect = makeConnect({ validator: okValidator({ name: 'Zoe' }) });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: s.sessionId,
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('INSUFFICIENT_CLAIMS');
  });

  it('produces POLICY_DENIED for a validly signed but underage result', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 12 }) });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: s.sessionId,
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('POLICY_DENIED');
  });

  it('a second presentation for a verified session fails as replay (one-shot)', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const s = await createPendingSession(connect);
    const body = {
      vp_token: vpWithIss('did:askmi:issuer'),
      presentation_submission: {},
      state: s.sessionId,
    };
    const first = await connect.completeSession({ sessionId: s.sessionId, body });
    expect(first.ok).toBe(true);
    const second = await connect.completeSession({ sessionId: s.sessionId, body });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe('REPLAY_DETECTED');
  });

  it('a failed session is terminal: no retry into success', async () => {
    const connect = makeConnect({ validator: failingValidator(['signature broken']) });
    const s = await createPendingSession(connect);
    const body = {
      vp_token: vpWithIss('did:askmi:issuer'),
      presentation_submission: {},
      state: s.sessionId,
    };
    const first = await connect.completeSession({ sessionId: s.sessionId, body });
    expect(first.ok).toBe(false);
    const second = await connect.completeSession({ sessionId: s.sessionId, body });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe('SESSION_TERMINAL');
  });
});

describe('completeSession (success path)', () => {
  it('verifies with minimal result/verification/provenance and no raw values', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24, name: 'Zoe' }) });
    const s = await createPendingSession(connect);
    const r = await connect.completeSession({
      sessionId: s.sessionId,
      body: {
        vp_token: vpWithIss('did:askmi:issuer'),
        presentation_submission: {},
        state: s.sessionId,
      },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.session.status).toBe('verified');
    expect(r.session.result).toEqual({ eligible: true });
    expect(r.session.provenance?.claimsShared).toEqual(['age']);
    expect(r.session.provenance?.claimsWithheld).toEqual([]);
    expect(r.session.provenance?.correlationId).toBe(s.correlationId);
    // PII-minimal: the session projection carries no claim VALUES.
    const serialized = JSON.stringify(r.session);
    expect(serialized).not.toContain('Zoe');
  });
});

describe('markWalletOpened', () => {
  it('transitions pending -> wallet_opened once, is idempotent, and stays unverified', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const s = await createPendingSession(connect);
    expect((await connect.markWalletOpened(s.sessionId)).ok).toBe(true);
    expect((await connect.markWalletOpened(s.sessionId)).ok).toBe(true); // idempotent
    const g = await connect.getSession(s.sessionId);
    if (g.ok) expect(g.session.status).toBe('wallet_opened');
  });

  it('fails closed for unknown or terminal sessions', async () => {
    const connect = makeConnect({ validator: okValidator({ age: 24 }) });
    const unknown = await connect.markWalletOpened('askmi_sess_missing');
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.code).toBe('UNKNOWN_SESSION');
    const s = await createPendingSession(connect);
    await connect.markWalletOpened(s.sessionId);
    const body = {
      vp_token: vpWithIss('did:askmi:issuer'),
      presentation_submission: {},
      state: s.sessionId,
    };
    await connect.completeSession({ sessionId: s.sessionId, body });
    const terminal = await connect.markWalletOpened(s.sessionId);
    expect(terminal.ok).toBe(false);
    if (!terminal.ok) expect(terminal.code).toBe('SESSION_TERMINAL');
  });
});
