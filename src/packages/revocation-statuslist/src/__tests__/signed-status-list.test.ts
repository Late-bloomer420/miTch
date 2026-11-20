import { describe, it, expect, beforeAll } from 'vitest';
import { StatusListRevocationChecker } from '../index';
import {
  makeStatusListCredential,
  makeStatusListEntry,
  signStatusListCredential,
  TEST_STATUS_LIST_ISSUER,
} from '../test-helpers';

// API-05 (2026-11-03 audit): status lists were parsed without any issuer signature check.

const ES256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
let issuer: CryptoKeyPair;
let attacker: CryptoKeyPair;

beforeAll(async () => {
  issuer = await crypto.subtle.generateKey(ES256, true, ['sign', 'verify']);
  attacker = await crypto.subtle.generateKey(ES256, true, ['sign', 'verify']);
});

// Index 2 revoked (MSB-first), everything else valid.
const encodedList = btoa(String.fromCharCode(0b00100000, 0, 0, 0));
const credential = () => makeStatusListCredential({ encodedList });

function fetchText(body: string): typeof fetch {
  return (async () => new Response(body, { status: 200 })) as typeof fetch;
}

function liveChecker(body: string, keyFor: (iss: string) => CryptoKey | null = () => issuer.publicKey) {
  return new StatusListRevocationChecker({
    statusListMode: 'live',
    fetchFn: fetchText(body),
    resolveStatusListKey: async (iss) => keyFor(iss),
  });
}

describe('API-05c: status list authenticity', () => {
  it('live: an unsigned JSON status list is rejected (fail-closed DENY)', async () => {
    const r = await liveChecker(JSON.stringify(credential())).checkRevocation(makeStatusListEntry(0), 'high');
    expect(r.decision).toBe('DENY');
    expect(r.reason).toBe('STATUS_SOURCE_UNAVAILABLE');
  });

  it('live: a signed status list from the resolved issuer key is accepted', async () => {
    const jws = await signStatusListCredential(credential(), issuer.privateKey);
    const checker = liveChecker(jws);
    expect((await checker.checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('ALLOW');
    const revoked = await checker.checkRevocation(makeStatusListEntry(2), 'high');
    expect(revoked).toMatchObject({ decision: 'DENY', revoked: true, reason: 'REVOKED' });
  });

  it('live: a list signed by another key is rejected (attacker clears a revocation bit)', async () => {
    const cleared = makeStatusListCredential({ encodedList: btoa(String.fromCharCode(0, 0, 0, 0)) });
    const jws = await signStatusListCredential(cleared, attacker.privateKey);
    const r = await liveChecker(jws).checkRevocation(makeStatusListEntry(2), 'high');
    expect(r.decision).toBe('DENY');
    expect(r.revoked).toBe(false);
  });

  it('live: payload tampering after signing is rejected', async () => {
    const jws = await signStatusListCredential(credential(), issuer.privateKey);
    const [h, , s] = jws.split('.');
    const forgedPayload = btoa(
      JSON.stringify({ iss: TEST_STATUS_LIST_ISSUER, vc: makeStatusListCredential({ encodedList: 'AAAAAA==' }) })
    ).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const r = await liveChecker(`${h}.${forgedPayload}.${s}`).checkRevocation(makeStatusListEntry(2), 'high');
    expect(r.decision).toBe('DENY');
    expect(r.revoked).toBe(false);
  });

  it('live: no key for the issuer, or no resolver at all → DENY', async () => {
    const jws = await signStatusListCredential(credential(), issuer.privateKey);
    expect((await liveChecker(jws, () => null).checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('DENY');
    const noResolver = new StatusListRevocationChecker({ statusListMode: 'live', fetchFn: fetchText(jws) });
    expect((await noResolver.checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('DENY');
  });

  it('live: wrong typ, and an expired signed list, are rejected', async () => {
    const wrongTyp = await signStatusListCredential(credential(), issuer.privateKey, { typ: 'JWT' });
    expect((await liveChecker(wrongTyp).checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('DENY');
    const expired = await signStatusListCredential(credential(), issuer.privateKey, {
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    expect((await liveChecker(expired).checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('DENY');
  });

  it('default mode is live (no ASKMI_TRUST_MODE=dev): unsigned lists are rejected', async () => {
    const prev = process.env.ASKMI_TRUST_MODE;
    delete process.env.ASKMI_TRUST_MODE;
    try {
      const checker = new StatusListRevocationChecker({ fetchFn: fetchText(JSON.stringify(credential())) });
      expect((await checker.checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('DENY');
    } finally {
      if (prev !== undefined) process.env.ASKMI_TRUST_MODE = prev;
    }
  });

  it('dev mode keeps accepting unsigned JSON for local mocks', async () => {
    const checker = new StatusListRevocationChecker({
      statusListMode: 'dev',
      fetchFn: fetchText(JSON.stringify(credential())),
    });
    expect((await checker.checkRevocation(makeStatusListEntry(0), 'high')).decision).toBe('ALLOW');
  });
});
