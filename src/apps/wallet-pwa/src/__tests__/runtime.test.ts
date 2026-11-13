import { describe, expect, it } from 'vitest';
import { runtimeOriginAllowed, walletRoute } from '../runtime';

describe('wallet entry and isolation boundary', () => {
  it('opens incoming sessions directly without a demo query flag', () => {
    expect(
      walletRoute('?state=askmi_sess_123&nonce=abc&request_uri=https%3A%2F%2Frp.example')
    ).toBe('wallet');
    expect(walletRoute('?endpoint=http://localhost:3004&scenario=liquor-store&sessionId=123')).toBe(
      'wallet'
    );
  });
  it('does not silently open an ordinary wallet for incomplete sessions', () => {
    expect(walletRoute('?state=askmi_sess_')).toBe('invalid');
    expect(walletRoute('?request_uri=')).toBe('invalid');
    expect(walletRoute('')).toBe('landing');
  });
  it('refuses to initialize a demo build on an existing wallet origin', () => {
    expect(runtimeOriginAllowed('http://localhost:5184', true)).toBe(true);
    expect(runtimeOriginAllowed('http://localhost:5174', true)).toBe(false);
    expect(runtimeOriginAllowed('https://localhost:5184', true)).toBe(false);
    expect(runtimeOriginAllowed('http://127.0.0.1:5184', true)).toBe(false);
  });
});
