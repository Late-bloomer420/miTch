import { describe, expect, it } from 'vitest';

import { canonicalizeJson, padPayload } from '../utils/anti-fingerprinting';

describe('anti-fingerprinting utilities', () => {
  it('canonicalizes nested JSON without dropping nested keys', () => {
    const canonical = canonicalizeJson({
      b: 2,
      a: {
        d: 4,
        c: 3,
      },
      arr: [
        {
          z: 1,
          y: 2,
        },
      ],
    });

    expect(canonical).toBe('{"a":{"c":3,"d":4},"arr":[{"y":2,"z":1}],"b":2}');
  });

  it('pads OID4VP direct-post payloads without stripping nested fields (ADOPT-0b: no issuer_jwk)', () => {
    // ADOPT-0b: the real credential path does NOT include issuer_jwk in the POST payload.
    const payload = {
      vp_token: 'token',
      presentation_submission: {
        id: 'presentation-submission',
        descriptor_map: [
          {
            id: 'age_input',
            format: 'vc+sd-jwt',
            path: '$',
          },
        ],
      },
      state: 'state-123',
    };

    const paddedPayload = padPayload(payload, 512);
    const parsed = JSON.parse(paddedPayload);

    expect(parsed.presentation_submission).toEqual(payload.presentation_submission);
    expect(parsed.issuer_jwk).toBeUndefined();
    expect(parsed.vp_token).toBe(payload.vp_token);
    expect(parsed.state).toBe(payload.state);
    expect(typeof parsed.padding).toBe('string');
  });

  it('wraps raw string payloads as ciphertext before padding', () => {
    const paddedPayload = padPayload('raw-jwe-token', 128);
    const parsed = JSON.parse(paddedPayload);

    expect(parsed.ciphertext).toBe('raw-jwe-token');
    expect(typeof parsed.padding).toBe('string');
  });
});
