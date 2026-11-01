import { describe, expect, it } from 'vitest';

import { buildAskMIHandoff } from '../src/browser/handoff';

describe('buildAskMIHandoff', () => {
  it('builds a handoff bound to the session state and nonce', () => {
    const handoff = buildAskMIHandoff({
      walletBaseUrl: 'https://wallet.example/',
      sessionId: 'askmi_sess_123',
      nonce: 'n0nce',
      presentationEndpoint: 'https://rp.example/askmi/connect/sessions/askmi_sess_123/presentation',
    });
    expect(handoff.method).toBe('browser-redirect-or-qr');
    expect(handoff.url).toBe('https://wallet.example?state=askmi_sess_123&nonce=n0nce');
    expect(handoff.presentationEndpoint).toBe(
      'https://rp.example/askmi/connect/sessions/askmi_sess_123/presentation'
    );
  });

  it('encodes unsafe characters and carries returnUrl as display metadata only', () => {
    const handoff = buildAskMIHandoff({
      walletBaseUrl: 'https://wallet.example',
      sessionId: 'askmi_sess_a/b c',
      nonce: 'n+ce',
      presentationEndpoint: 'https://rp.example/present',
      returnUrl: 'https://rp.example/after',
    });
    const url = new URL(handoff.url);
    expect(url.searchParams.get('state')).toBe('askmi_sess_a/b c');
    expect(url.searchParams.get('nonce')).toBe('n+ce');
    expect(url.searchParams.get('returnUrl')).toBe('https://rp.example/after');
  });
});
