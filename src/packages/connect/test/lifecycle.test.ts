import { ASKMI_SCENARIO_VCT } from '@askmi/shared-types';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createAskMIConnect } from '../src/core/verifier';
import { InMemoryAskMIConnectSessionStore } from '../src/core/session-store';
import { askmiConnectExpressRouter } from '../src/express/router';
import type { AskMIConnectSessionUpdate, PresentationValidator } from '../src/core/types';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

const key = {} as CryptoKey;
const valid = { ok: true, disclosedClaims: { age: 24 }, errors: [] };
const body = {
  vp_token: `header.${btoa(JSON.stringify({ iss: 'did:askmi:issuer', vct: ASKMI_SCENARIO_VCT['liquor-store'] }))}.sig~kb`,
  presentation_submission: {
    definition_id: 'askmi-connect',
    descriptor_map: [{ id: 'age-credential', format: 'sd-jwt', path: '$' }],
  },
};

function fixture(
  options: {
    resolver?: (iss: string) => Promise<CryptoKey | null>;
    validator?: PresentationValidator;
    store?: InMemoryAskMIConnectSessionStore;
  } = {}
) {
  let time = Date.parse('2026-10-24T08:00:00Z');
  const now = () => time;
  const store = options.store ?? new InMemoryAskMIConnectSessionStore(now);
  const connect = createAskMIConnect({
    verifierDid: 'did:askmi:verifier',
    audienceBaseUrl: 'https://rp.example',
    walletBaseUrl: 'https://wallet.example',
    sessionTtlMs: 1000,
    now,
    store,
    issuerKeyResolver: options.resolver ?? (async () => key),
    presentationValidator: options.validator ?? (async () => valid),
  });
  const app = express();
  app.use(express.json());
  app.use(askmiConnectExpressRouter(connect));
  return {
    connect,
    store,
    app,
    expire: () => {
      time += 1000;
    },
    now,
  };
}

async function create(f: ReturnType<typeof fixture>) {
  const result = await f.connect.createSession({ policyId: 'age-liquor-store-v1' });
  if (!result.ok) throw new Error('creation failed');
  return result.session;
}

describe('resolver failure is one terminal attempt', () => {
  it('distinguishes lookup failure from untrusted issuer, never retries the dead session', async () => {
    let calls = 0;
    const f = fixture({
      resolver: async () => {
        if (++calls === 1) throw new Error('private JWKS URL and diagnostics');
        return key;
      },
    });
    const first = await create(f);
    const failed = await f.connect.completeSession({
      sessionId: first.sessionId,
      body: { ...body, state: first.sessionId },
    });
    expect(failed).toMatchObject({ ok: false, code: 'ISSUER_RESOLUTION_FAILED' });
    expect(JSON.stringify(failed)).not.toContain('private');
    expect(await f.connect.getSession(first.sessionId)).toMatchObject({
      ok: true,
      session: { status: 'failed', errorCode: 'ISSUER_RESOLUTION_FAILED' },
    });
    expect(
      await f.connect.completeSession({
        sessionId: first.sessionId,
        body: { ...body, state: first.sessionId },
      })
    ).toMatchObject({
      ok: false,
      code: 'SESSION_TERMINAL',
    });
    expect(calls).toBe(1);
    const fresh = await create(f);
    expect(fresh.nonce).not.toBe(first.nonce);
    expect(
      await f.connect.completeSession({
        sessionId: fresh.sessionId,
        body: { ...body, state: fresh.sessionId },
      })
    ).toMatchObject({
      ok: true,
    });
    const untrusted = fixture({ resolver: async () => null });
    const other = await create(untrusted);
    expect(
      await untrusted.connect.completeSession({
        sessionId: other.sessionId,
        body: { ...body, state: other.sessionId },
      })
    ).toMatchObject({
      ok: false,
      code: 'UNTRUSTED_ISSUER',
    });
  });

  it('answers HTTP 503 with a stable code and persists failure before responding', async () => {
    const f = fixture({
      resolver: async () => {
        throw new Error('secret');
      },
    });
    const s = await create(f);
    const res = await request(f.app)
      .post(`/askmi/connect/sessions/${s.sessionId}/presentation`)
      .send({ ...body, state: s.sessionId });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('ISSUER_RESOLUTION_FAILED');
    expect(JSON.stringify(res.body)).not.toContain('secret');
    expect((await f.store.get(s.sessionId))?.status).toBe('failed');
  });
});

describe('TTL checked atomically at completion', () => {
  for (const gate of ['resolver', 'validator'] as const) {
    for (const poll of [false, true]) {
      for (const outcome of ['allow', 'deny', 'throw'] as const) {
        it(`${gate}, poll=${poll}, late ${outcome}: expiry is absorbing`, async () => {
          const entered = deferred<void>();
          const release = deferred<void>();
          const wait = async () => {
            entered.resolve();
            await release.promise;
          };
          const validator: PresentationValidator = async () => {
            if (gate === 'validator') await wait();
            if (outcome === 'throw') throw new Error('secret');
            return outcome === 'allow' ? valid : { ok: false, errors: ['signature invalid'] };
          };
          const f = fixture({
            resolver: async () => {
              if (gate === 'resolver') await wait();
              return key;
            },
            validator,
          });
          const s = await create(f);
          await f.connect.markWalletOpened(s.sessionId);
          const completion = f.connect.completeSession({
            sessionId: s.sessionId,
            body: { ...body, state: s.sessionId },
          });
          await entered.promise;
          f.expire();
          if (poll)
            expect(await f.connect.getSession(s.sessionId)).toMatchObject({
              session: { status: 'expired' },
            });
          release.resolve();
          expect(await completion).toMatchObject({ ok: false, code: 'SESSION_EXPIRED' });
          expect(await f.connect.getSession(s.sessionId)).toMatchObject({
            session: { status: 'expired' },
          });
          const stored = await f.store.get(s.sessionId);
          expect(stored?.result).toBeUndefined();
          expect(stored?.errorCode).toBeUndefined();
        });
      }
    }
  }

  it('discards a resolver rejection after expiry', async () => {
    const entered = deferred<void>();
    const release = deferred<CryptoKey | null>();
    const f = fixture({
      resolver: () => {
        entered.resolve();
        return release.promise;
      },
    });
    const s = await create(f);
    const completion = f.connect.completeSession({
      sessionId: s.sessionId,
      body: { ...body, state: s.sessionId },
    });
    await entered.promise;
    f.expire();
    release.reject(new Error('lookup timed out'));
    expect(await completion).toMatchObject({ ok: false, code: 'SESSION_EXPIRED' });
    expect((await f.store.get(s.sessionId))?.status).toBe('expired');
  });

  it('does not recreate a record deleted during verification', async () => {
    const entered = deferred<void>();
    const release = deferred<void>();
    const f = fixture({
      resolver: async () => {
        entered.resolve();
        await release.promise;
        return key;
      },
    });
    const s = await create(f);
    const completion = f.connect.completeSession({
      sessionId: s.sessionId,
      body: { ...body, state: s.sessionId },
    });
    await entered.promise;
    f.expire();
    expect(await f.store.deleteExpired(new Date(f.now()))).toBe(1);
    release.resolve();
    expect(await completion).toMatchObject({ ok: false, code: 'UNKNOWN_SESSION' });
    expect(await f.store.get(s.sessionId)).toBeNull();
  });

  it('rejects concurrent replay while the first resolution is paused', async () => {
    const entered = deferred<void>();
    const release = deferred<void>();
    const f = fixture({
      resolver: async () => {
        entered.resolve();
        await release.promise;
        return key;
      },
    });
    const s = await create(f);
    const first = f.connect.completeSession({
      sessionId: s.sessionId,
      body: { ...body, state: s.sessionId },
    });
    await entered.promise;
    expect(
      await f.connect.completeSession({
        sessionId: s.sessionId,
        body: { ...body, state: s.sessionId },
      })
    ).toMatchObject({
      ok: false,
      code: 'REPLAY_DETECTED',
    });
    release.resolve();
    expect(await first).toMatchObject({ ok: true });
  });
});

describe('terminal states reject every later transition', () => {
  for (const terminal of ['verified', 'failed', 'expired'] as const) {
    it(`preserves ${terminal} against late opened, deny and success writes`, async () => {
      const f = fixture();
      const s = await create(f);
      if (terminal === 'verified')
        await f.connect.completeSession({
          sessionId: s.sessionId,
          body: { ...body, state: s.sessionId },
        });
      if (terminal === 'failed') await f.connect.failSession(s.sessionId);
      if (terminal === 'expired') f.expire();
      for (const update of [
        { status: 'wallet_opened' },
        { status: 'failed', errorCode: 'INTERNAL_ERROR' },
        {
          status: 'verified',
          result: { eligible: true },
          verification: {
            cryptographic: 'passed',
            issuerTrust: 'passed',
            policy: 'allowed',
            userApproval: 'presentation_received',
          },
          provenance: {
            policyId: s.policyId,
            policyVersion: 1,
            credentialProfile: 'sd-jwt-vc-age-v1',
            claimsShared: ['age'],
            claimsWithheld: [],
            correlationId: s.correlationId,
          },
        },
      ] satisfies AskMIConnectSessionUpdate[]) {
        expect(await f.store.update(s.sessionId, update)).toMatchObject({
          applied: false,
          session: { status: terminal },
        });
      }
    });
  }

  it('does not allow a returned snapshot to mutate the stored state', async () => {
    const f = fixture();
    const s = await create(f);
    const snapshot = await f.store.get(s.sessionId);
    Object.assign(snapshot!, { status: 'verified' });
    expect((await f.store.get(s.sessionId))?.status).toBe('pending');
  });
});

describe('unexpected exceptions', () => {
  it('persists INTERNAL_ERROR on an unexpected policy evaluation error', async () => {
    const claims = {
      get age(): number {
        throw new Error('private value');
      },
    };
    const f = fixture({
      validator: async () => ({ ok: true, disclosedClaims: claims, errors: [] }),
    });
    const s = await create(f);
    expect(
      await f.connect.completeSession({
        sessionId: s.sessionId,
        body: { ...body, state: s.sessionId },
      })
    ).toMatchObject({
      ok: false,
      code: 'INTERNAL_ERROR',
    });
    expect((await f.store.get(s.sessionId))?.errorCode).toBe('INTERNAL_ERROR');
  });

  it('persists a core failure when consume unexpectedly rejects', async () => {
    const f = fixture();
    const session = await create(f);
    f.store.consume = async () => {
      throw new Error('private backend error');
    };
    expect(
      await f.connect.completeSession({
        sessionId: session.sessionId,
        body: { ...body, state: session.sessionId },
      })
    ).toMatchObject({
      ok: false,
      code: 'INTERNAL_ERROR',
    });
    expect((await f.store.get(session.sessionId))?.errorCode).toBe('INTERNAL_ERROR');
  });

  it('catches a creation rejection without leaking diagnostics over HTTP', async () => {
    const f = fixture();
    f.connect.createSession = async () => {
      throw new Error('private configuration');
    };
    const response = await request(f.app)
      .post('/askmi/connect/sessions')
      .send({ policyId: 'age-liquor-store-v1' });
    expect(response.status).toBe(500);
    expect(response.body.error.code).toBe('INTERNAL_ERROR');
    expect(JSON.stringify(response.body)).not.toContain('private configuration');
  });

  for (const route of ['opened', 'presentation', 'status'] as const) {
    it(`HTTP catch-all persists failure after an unexpected ${route} rejection`, async () => {
      const f = fixture();
      const s = await create(f);
      const method =
        route === 'opened'
          ? 'markWalletOpened'
          : route === 'status'
            ? 'getSession'
            : 'completeSession';
      f.connect[method] = async () => {
        throw new Error('private failure');
      };
      const url = `/askmi/connect/sessions/${s.sessionId}${route === 'status' ? '' : `/${route}`}`;
      const res =
        route === 'status'
          ? await request(f.app).get(url)
          : await request(f.app)
              .post(url)
              .send({ ...body, state: s.sessionId });
      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe('INTERNAL_ERROR');
      expect(JSON.stringify(res.body)).not.toContain('private failure');
      expect((await f.store.get(s.sessionId))?.status).toBe('failed');
    });
  }

  it('reports unconfirmed persistence if the store cannot write, never a fabricated terminal state', async () => {
    const f = fixture();
    const s = await create(f);
    f.connect.completeSession = async () => {
      throw new Error('private failure');
    };
    f.store.update = async () => {
      throw new Error('store unavailable');
    };
    const res = await request(f.app)
      .post(`/askmi/connect/sessions/${s.sessionId}/presentation`)
      .send({ ...body, state: s.sessionId });
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('unknown');
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
    expect((await f.store.get(s.sessionId))?.status).toBe('pending');
  });

  it('never returns raw unrecognised validation messages', async () => {
    const f = fixture({ validator: async () => ({ ok: false, errors: ['private diagnostic'] }) });
    const s = await create(f);
    const res = await request(f.app)
      .post(`/askmi/connect/sessions/${s.sessionId}/presentation`)
      .send({ ...body, state: s.sessionId });
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).not.toContain('private diagnostic');
  });
});
