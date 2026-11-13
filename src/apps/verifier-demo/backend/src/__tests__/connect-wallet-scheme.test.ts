import { afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

// app.ts reads the wallet base URL once at import, so each case imports it fresh.
async function handoffOrigin(env: Record<string, string | undefined>): Promise<string> {
  vi.resetModules();
  for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
  const { app } = await import('../app');
  const created = await request(app)
    .post('/askmi/connect/sessions')
    .send({ policyId: 'age-liquor-store-v1' })
    .expect(201);
  return new URL(created.body.handoff.url).origin;
}

describe('Connect handoff wallet scheme', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('defaults to the HTTPS wallet dev server', async () => {
    expect(await handoffOrigin({ WALLET_BASE_URL: undefined, ASKMI_DEV_HTTPS: undefined })).toBe(
      'https://localhost:5174'
    );
  });

  it('follows the ASKMI_DEV_HTTPS=0 opt-out to HTTP', async () => {
    expect(await handoffOrigin({ WALLET_BASE_URL: undefined, ASKMI_DEV_HTTPS: '0' })).toBe(
      'http://localhost:5174'
    );
  });

  it('lets an explicit WALLET_BASE_URL win over the opt-out', async () => {
    expect(
      await handoffOrigin({ WALLET_BASE_URL: 'https://wallet.example', ASKMI_DEV_HTTPS: '0' })
    ).toBe('https://wallet.example');
  });
});
