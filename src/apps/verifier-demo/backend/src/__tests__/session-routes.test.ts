import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../app';

describe('session guards on route aliases', () => {
  it('requires sessions on every accepted spelling of a stateful route', async () => {
    for (const route of [
      '/status',
      '/authorize',
      '/notify-scan',
      '/wallet-present',
      '/oid4vp-present',
      '/present',
      '/reset',
    ]) {
      for (const variant of [route, `${route}/`, route.toUpperCase()]) {
        const client = request(app);
        const response = await (route === '/status' || route === '/authorize'
          ? client.get(variant)
          : client.post(variant));
        expect(response.status, variant).toBe(400);
        expect(response.body.error, variant).toBe('MISSING_SESSION_ID');
      }
    }
  });

  it('preserves isolation when callers use route aliases', async () => {
    await request(app).post('/NOTIFY-SCAN/').set('X-AskMI-Session-Id', 'alias-alice').expect(200);
    const alice = await request(app).get('/status/').set('X-AskMI-Session-Id', 'alias-alice');
    const bob = await request(app).get('/STATUS').set('X-AskMI-Session-Id', 'alias-bob');
    expect(alice.body.status).toBe('SCANNED');
    expect(bob.body.status).toBe('WAITING');
  });
});
