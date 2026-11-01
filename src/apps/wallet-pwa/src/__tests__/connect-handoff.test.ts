import { describe, expect, it, vi } from 'vitest';
import {
  parseConnectHandoff,
  loadConnectRequest,
  presentationAccepted,
} from '../utils/connect-handoff';

const requestUri = 'https://rp.example/askmi/connect/sessions/askmi_sess_test/request';
const query = `?state=askmi_sess_test&nonce=server-nonce&request_uri=${encodeURIComponent(requestUri)}`;
const auth = {
  state: 'askmi_sess_test',
  nonce: 'server-nonce',
  client_id: 'did:web:rp.example',
  redirect_uri: 'https://rp.example/askmi/connect/sessions/askmi_sess_test/presentation',
  response_type: 'vp_token',
  response_mode: 'direct_post',
};

describe('Connect wallet handoff', () => {
  it('loads the server request without minting a legacy authorization', async () => {
    const input = parseConnectHandoff(query)!;
    const fetcher = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({ authRequest: auth }) });
    expect(await loadConnectRequest(input, fetcher)).toEqual(auth);
    expect(fetcher).toHaveBeenCalledExactlyOnceWith(requestUri, {
      redirect: 'error',
      cache: 'no-store',
    });
  });
  it.each([
    { state: 'other' },
    { nonce: 'other' },
    { redirect_uri: 'https://other.example/collect' },
  ])('rejects substituted bindings %j', async (change) => {
    const fetcher = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({ authRequest: { ...auth, ...change } }) });
    await expect(loadConnectRequest(parseConnectHandoff(query)!, fetcher)).rejects.toThrow(
      'does not match'
    );
  });
  it('rejects missing state and mismatched request paths', () => {
    expect(() => parseConnectHandoff(`?request_uri=${encodeURIComponent(requestUri)}`)).toThrow();
    expect(() =>
      parseConnectHandoff(query.replace('state=askmi_sess_test', 'state=other'))
    ).toThrow();
  });
  it('never turns an HTTP failure or unverified result into wallet success', () => {
    expect(presentationAccepted(true, { ok: true, status: 'failed' })).toBe(false);
    expect(presentationAccepted(true, { status: 'verified', result: { eligible: true } })).toBe(
      true
    );
    expect(presentationAccepted(false, { status: 'verified', result: { eligible: true } })).toBe(
      false
    );
    expect(presentationAccepted(true, { status: 'pending', result: { eligible: true } })).toBe(
      false
    );
    expect(presentationAccepted(true, { status: 'verified', result: { eligible: false } })).toBe(
      false
    );
  });
});
