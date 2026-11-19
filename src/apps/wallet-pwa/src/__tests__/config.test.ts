import { afterEach, describe, expect, it, vi } from 'vitest';

async function verifierEndpoint(mode: string, configured = ''): Promise<string> {
  vi.resetModules();
  vi.stubEnv('MODE', mode);
  vi.stubEnv('VITE_VERIFIER_URL', configured);
  const { CONFIG } = await import('../config');
  return CONFIG.VERIFIER_ENDPOINT;
}

describe('verifier endpoint', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('uses the demo verifier in a demo build without configuration', async () => {
    expect(await verifierEndpoint('demo')).toBe('http://localhost:3104/present');
  });

  it('keeps the regular verifier outside demo builds', async () => {
    expect(await verifierEndpoint('development')).toBe('http://localhost:3004/present');
  });

  it('prefers a configured verifier in a demo build', async () => {
    expect(await verifierEndpoint('demo', 'http://localhost:4000/present')).toBe(
      'http://localhost:4000/present'
    );
  });
});
