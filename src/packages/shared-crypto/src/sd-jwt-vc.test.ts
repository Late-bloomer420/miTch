import { describe, it, expect } from 'vitest';
import { createSDJWTDisclosures } from './sd-jwt-vc';
import { sha256 } from '@noble/hashes/sha2.js';

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('createSDJWTDisclosures', () => {
  it('produces one disclosure + one digest per claim, digest = sha256(disclosure)', async () => {
    const { _sd, disclosures } = await createSDJWTDisclosures({ dateOfBirth: '1990-01-01', isOver18: true });
    expect(_sd).toHaveLength(2);
    expect(disclosures).toHaveLength(2);
    for (let i = 0; i < disclosures.length; i++) {
      expect(_sd).toContain(b64url(sha256(new TextEncoder().encode(disclosures[i]))));
    }
  });
  it('each disclosure decodes to [salt, name, value] with distinct salts', async () => {
    const { disclosures } = await createSDJWTDisclosures({ a: 1, b: 2 });
    const decoded = disclosures.map((d) =>
      JSON.parse(Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString())
    );
    expect(decoded[0][1]).toBe('a');
    expect(decoded[1][1]).toBe('b');
    expect(decoded[0][0]).not.toBe(decoded[1][0]); // distinct salts
  });
});
