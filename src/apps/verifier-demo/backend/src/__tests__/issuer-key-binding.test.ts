import { expect, it, vi } from 'vitest';
import { trustListResolver } from '@askmi/shared-crypto';
import { ASKMI_DEMO } from '@askmi/shared-types';
import { defaultResolveIssuerKey } from '../app';

it('does not assign the configured demo JWKS key to another trust-listed issuer', async () => {
  const otherIssuer = 'did:web:other.example';
  trustListResolver.setFetch(
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        id: 'test',
        version: '1',
        validUntil: '2030-01-01T00:00:00Z',
        issuers: [ASKMI_DEMO.issuerUri, otherIssuer],
      }),
    })
  );
  trustListResolver.clearCache();
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ keys: [jwk] }) });
  vi.stubGlobal('fetch', fetcher);
  try {
    expect(await defaultResolveIssuerKey(otherIssuer)).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
    expect(await defaultResolveIssuerKey(ASKMI_DEMO.issuerUri)).not.toBeNull();
  } finally {
    vi.unstubAllGlobals();
  }
});
