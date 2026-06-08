import { describe, it, expect } from 'vitest';
import { generateHolderBinding } from './holder-binding';
import { createKeyBindingJWT, validateKeyBindingJWT } from './sd-jwt-vc';

describe('generateHolderBinding', () => {
  it('produces a well-formed P-256 cnf JWK', async () => {
    const { cnf } = await generateHolderBinding();
    expect(cnf.jwk).toBeDefined();
    expect(cnf.jwk?.kty).toBe('EC');
    expect(cnf.jwk?.crv).toBe('P-256');
    expect(typeof cnf.jwk?.x).toBe('string');
    expect(typeof cnf.jwk?.y).toBe('string');
    // public-only: a holder cnf must never carry the private scalar
    expect((cnf.jwk as unknown as Record<string, unknown>).d).toBeUndefined();
  });

  it('yields a distinct holder key on each call (unlinkability foundation)', async () => {
    const a = await generateHolderBinding();
    const b = await generateHolderBinding();
    // different key material → different x/y coordinates
    expect(a.cnf.jwk?.x).not.toBe(b.cnf.jwk?.x);
    expect(a.cnf.jwk?.y).not.toBe(b.cnf.jwk?.y);
  });

  it('round-trips: KB-JWT signed by the binding validates against its own cnf', async () => {
    const binding = await generateHolderBinding();
    const opts = {
      aud: 'https://verifier.askmi.demo',
      nonce: 'nonce-123',
      sdJwtWithDisclosures: 'header.payload.sig~disclosure1~',
    };
    const kbJwt = await createKeyBindingJWT(opts, binding.keyPair.privateKey);

    const result = await validateKeyBindingJWT(kbJwt, binding.cnf.jwk!, {
      expectedAud: opts.aud,
      expectedNonce: opts.nonce,
      sdJwtWithDisclosures: opts.sdJwtWithDisclosures,
    });
    expect(result.ok).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('cross-binding fails: a KB-JWT from binding A does not validate against cnf B', async () => {
    const a = await generateHolderBinding();
    const b = await generateHolderBinding();
    const opts = {
      aud: 'https://verifier.askmi.demo',
      nonce: 'nonce-xyz',
      sdJwtWithDisclosures: 'header.payload.sig~disclosure1~',
    };
    const kbJwtFromA = await createKeyBindingJWT(opts, a.keyPair.privateKey);

    const result = await validateKeyBindingJWT(kbJwtFromA, b.cnf.jwk!, {
      expectedAud: opts.aud,
      expectedNonce: opts.nonce,
      sdJwtWithDisclosures: opts.sdJwtWithDisclosures,
    });
    expect(result.ok).toBe(false);
  });
});
