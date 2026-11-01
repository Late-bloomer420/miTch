import { describe, expect, it } from 'vitest';

import { InMemoryAskMIConnectSessionStore } from '../src/core/session-store';
import type { AskMIConnectSession } from '../src/core/types';

function makeSession(overrides: Partial<AskMIConnectSession> = {}): AskMIConnectSession {
  const now = new Date();
  return {
    sessionId: 'askmi_sess_test',
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString(),
    nonce: 'n',
    audience: 'https://rp.example/askmi/connect/sessions/askmi_sess_test/presentation',
    verifierDid: 'did:askmi:verifier',
    policyId: 'age-liquor-store-v1',
    policyVersion: 1,
    correlationId: 'txn_test',
    ...overrides,
  };
}

describe('InMemoryAskMIConnectSessionStore', () => {
  it('creates, gets and updates sessions', async () => {
    const store = new InMemoryAskMIConnectSessionStore();
    const session = makeSession();
    await store.create(session);
    expect((await store.get('askmi_sess_test'))?.status).toBe('pending');
    await store.update(session.sessionId, { status: 'wallet_opened' });
    expect((await store.get('askmi_sess_test'))?.status).toBe('wallet_opened');
  });

  it('rejects session id collisions', async () => {
    const store = new InMemoryAskMIConnectSessionStore();
    await store.create(makeSession());
    await expect(store.create(makeSession())).rejects.toThrow(/collision/);
  });

  it('does not recreate an unknown session', async () => {
    const store = new InMemoryAskMIConnectSessionStore();
    expect(
      await store.update('missing', { status: 'failed', errorCode: 'INTERNAL_ERROR' })
    ).toEqual({ applied: false, session: null });
  });

  it('consumes one-shot: a second consume returns null (replay)', async () => {
    const store = new InMemoryAskMIConnectSessionStore();
    await store.create(makeSession());
    expect(await store.consume('askmi_sess_test')).not.toBeNull();
    expect(await store.consume('askmi_sess_test')).toBeNull();
    // The record itself stays readable for status visibility.
    expect(await store.get('askmi_sess_test')).not.toBeNull();
  });

  it('consume returns null for an unknown session', async () => {
    const store = new InMemoryAskMIConnectSessionStore();
    expect(await store.consume('askmi_sess_missing')).toBeNull();
  });

  it('deleteExpired removes only expired sessions and returns the count', async () => {
    const store = new InMemoryAskMIConnectSessionStore();
    const now = new Date('2026-10-23T12:00:00Z');
    await store.create(makeSession({ sessionId: 'fresh', expiresAt: '2026-10-23T12:01:00Z' }));
    await store.create(makeSession({ sessionId: 'stale', expiresAt: '2026-10-23T11:59:00Z' }));
    await store.create(
      makeSession({ sessionId: 'flagged', status: 'expired', expiresAt: '2026-10-23T12:05:00Z' })
    );
    expect(await store.deleteExpired(now)).toBe(2);
    expect(await store.get('fresh')).not.toBeNull();
    expect(await store.get('stale')).toBeNull();
    expect(await store.get('flagged')).toBeNull();
  });
});
