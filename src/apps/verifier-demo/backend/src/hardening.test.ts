import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';

beforeEach(() => {
  vi.resetModules();
  process.env.ASKMI_TEST_MODE = '1';
  delete process.env.CORS_ALLOWED_ORIGINS;
  delete process.env.VERIFIER_KEY_PERSISTENCE;
  delete process.env.MAX_VERIFIER_SESSIONS;
});
afterEach(() => vi.restoreAllMocks());

describe('verifier backend hardening', () => {
  it('denies browser origins unless explicitly allowlisted', async () => {
    const { app } = await import('./app');
    const denied = await request(app).get('/health').set('Origin', 'https://evil.example').expect(403);
    expect(denied.body.error).toBe('CORS_ORIGIN_DENIED');
  });

  it('isolates verification state between concurrent sessions', async () => {
    const { app } = await import('./app');
    await request(app).post('/notify-scan').set('X-AskMI-Session-Id', 'alice').expect(200);
    expect((await request(app).get('/status').set('X-AskMI-Session-Id', 'alice')).body.status).toBe('SCANNED');
    expect((await request(app).get('/status').set('X-AskMI-Session-Id', 'bob')).body.status).toBe('WAITING');
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'alice').expect(200);
    expect((await request(app).get('/status').set('X-AskMI-Session-Id', 'bob')).body.status).toBe('WAITING');
  });

  it('rejects malformed or oversized session identifiers', async () => {
    const { app } = await import('./app');
    const malformed = await request(app)
      .get('/status')
      .set('X-AskMI-Session-Id', '../shared-state')
      .expect(400);
    expect(malformed.body.error).toBe('INVALID_SESSION_ID');

    await request(app)
      .get('/status')
      .set('X-AskMI-Session-Id', 'a'.repeat(129))
      .expect(400);
  });

  it('rejects missing session identifiers on every stateful verification endpoint', async () => {
    const { app } = await import('./app');
    const statefulRequests = [
      () => request(app).get('/status'),
      () => request(app).post('/notify-scan'),
      () => request(app).get('/authorize'),
      () => request(app).post('/wallet-present'),
      () => request(app).post('/oid4vp-present'),
      () => request(app).post('/present'),
      () => request(app).post('/reset'),
    ];

    for (const makeRequest of statefulRequests) {
      const response = await makeRequest().expect(400);
      expect(response.body.error).toBe('MISSING_SESSION_ID');
    }
  });

  it('echoes the caller-created session through authorization', async () => {
    const { app } = await import('./app');
    const response = await request(app)
      .get('/authorize?scenario=liquor-store')
      .set('X-AskMI-Session-Id', 'full-flow-session')
      .expect(200);

    expect(response.headers['x-askmi-session-id']).toBe('full-flow-session');
    expect(response.body.sessionId).toBe('full-flow-session');
  });

  it('rejects conflicting session identifiers instead of guessing which one to trust', async () => {
    const { app } = await import('./app');
    const response = await request(app)
      .post('/notify-scan?sessionId=query-session')
      .set('X-AskMI-Session-Id', 'header-session')
      .send({ sessionId: 'body-session' })
      .expect(400);
    expect(response.body.error).toBe('INVALID_SESSION_ID');
  });

  it.each(['http://localhost:5174', 'http://localhost:5175'])(
    'allows the configured demo browser origin %s',
    async (origin) => {
      process.env.CORS_ALLOWED_ORIGINS = 'http://localhost:5174,http://localhost:5175';
      const { app } = await import('./app');
      const response = await request(app).get('/health').set('Origin', origin).expect(200);
      expect(response.headers['access-control-allow-origin']).toBe(origin);
    }
  );

  it('enforces the session cap on reset requests', async () => {
    process.env.MAX_VERIFIER_SESSIONS = '2';
    const { app } = await import('./app');

    await request(app).post('/notify-scan').set('X-AskMI-Session-Id', 'first').expect(200);
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'second').expect(200);
    await request(app).post('/reset').set('X-AskMI-Session-Id', 'third').expect(200);

    const evicted = await request(app).get('/status').set('X-AskMI-Session-Id', 'first').expect(200);
    expect(evicted.body.status).toBe('WAITING');
  });

  it('keeps generated verifier private keys ephemeral by default', async () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'askmi-verifier-'));
    const previous = process.cwd();
    try {
      process.chdir(temp);
      delete process.env.ASKMI_TEST_MODE;
      vi.resetModules();
      const { getVerifierKeys } = await import('./app');
      await getVerifierKeys();
      expect(fs.existsSync(path.join(temp, 'verifier-key.json'))).toBe(false);
    } finally {
      process.chdir(previous);
      fs.rmSync(temp, { recursive: true, force: true });
    }
  }, 30_000);
});
