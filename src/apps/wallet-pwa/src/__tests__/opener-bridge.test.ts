import { describe, expect, it } from 'vitest';
import { parseOpenerOrigins, readOpenerRequest } from '../utils/opener-bridge';

// #239: the popup bridge must ignore every message that does not come from the
// window that opened the wallet, at an origin the deployment configured.
const opener = {} as MessageEventSource;
const allowed = ['https://shop.example'];
const request = {
  type: 'ASKMI_OID4VP_REQUEST',
  scenario: 'liquor-store',
  endpoint: 'https://shop.example/api',
  verifier: 'did:web:shop.example',
  sessionId: 'session-1',
};
const message = (overrides: Partial<{ origin: string; source: unknown; data: unknown }> = {}) => ({
  origin: 'https://shop.example',
  source: opener,
  data: request,
  ...overrides,
});

describe('parseOpenerOrigins', () => {
  it('is empty when nothing is configured, so the bridge stays off', () => {
    expect(parseOpenerOrigins(undefined)).toEqual([]);
    expect(parseOpenerOrigins('  ')).toEqual([]);
  });

  it('normalises entries to origins and drops unusable ones', () => {
    expect(
      parseOpenerOrigins('https://Shop.Example/path, http://localhost:5175 ,not a url,*,null')
    ).toEqual(['https://shop.example', 'http://localhost:5175']);
  });

  it('keeps only http and https origins', () => {
    expect(parseOpenerOrigins('file:///tmp/x,javascript:alert(1),data:text/html,x')).toEqual([]);
  });
});

describe('readOpenerRequest', () => {
  it('returns the request from the opener at an allowed origin', () => {
    expect(readOpenerRequest(message(), opener, allowed)).toEqual({
      scenario: 'liquor-store',
      endpoint: 'https://shop.example/api',
      verifier: 'did:web:shop.example',
      sessionId: 'session-1',
    });
  });

  it('accepts the legacy message type', () => {
    const legacy = message({ data: { ...request, type: 'MITCH_OID4VP_REQUEST' } });
    expect(readOpenerRequest(legacy, opener, allowed)).not.toBeNull();
  });

  it('ignores every message when no origin is configured', () => {
    expect(readOpenerRequest(message(), opener, [])).toBeNull();
  });

  it('ignores a foreign origin, including look-alikes', () => {
    for (const origin of [
      'https://evil.example',
      'https://shop.example.evil.net',
      'http://shop.example',
      'https://shop.example:8443',
      'null',
      '',
    ]) {
      expect(readOpenerRequest(message({ origin }), opener, allowed)).toBeNull();
    }
  });

  it('ignores an allowed origin when the sender is not the opener window', () => {
    const iframe = {} as MessageEventSource;
    expect(readOpenerRequest(message({ source: iframe }), opener, allowed)).toBeNull();
    expect(readOpenerRequest(message({ source: null }), opener, allowed)).toBeNull();
  });

  it('ignores messages when the wallet has no opener', () => {
    expect(readOpenerRequest(message({ source: null }), null, allowed)).toBeNull();
    expect(readOpenerRequest(message(), null, allowed)).toBeNull();
  });

  it('ignores other message types and malformed payloads', () => {
    for (const data of [
      null,
      'ASKMI_OID4VP_REQUEST',
      { type: 'SOMETHING_ELSE' },
      { ...request, endpoint: undefined },
      { ...request, sessionId: 42 },
      { ...request, scenario: '' },
    ]) {
      expect(readOpenerRequest(message({ data }), opener, allowed)).toBeNull();
    }
  });
});
