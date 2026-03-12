import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  VerifierDirectClient,
  WalletDirectProtocol,
} from '../src/index.js';
import type { PresentationRequest, VerificationResponse } from '../src/index.js';

// ---------------------------------------------------------------------------
// VerifierDirectClient
// ---------------------------------------------------------------------------
describe('VerifierDirectClient', () => {
  let verifier: VerifierDirectClient;

  beforeEach(async () => {
    verifier = new VerifierDirectClient('did:mitch:verifier-liquor-store');
    await verifier.initialize();
  });

  it('initializes without throwing', async () => {
    const v = new VerifierDirectClient('did:mitch:test');
    await expect(v.initialize()).resolves.toBeUndefined();
  });

  it('generates a deep link with mitch:// scheme', async () => {
    const deepLink = await verifier.generateRequest(
      ['AgeCredential'],
      'https://liquor-store.com/api/verify',
    );
    expect(deepLink).toMatch(/^mitch:\/\/present\?request=/);
  });

  it('deep link contains a JWT with 3 parts', async () => {
    const deepLink = await verifier.generateRequest(
      ['AgeCredential'],
      'https://example.com/verify',
    );
    const url = new URL(deepLink);
    const jwt = url.searchParams.get('request')!;
    const decoded = decodeURIComponent(jwt);
    const parts = decoded.split('.');
    expect(parts).toHaveLength(3);
  });

  it('JWT payload contains verifierDID and credentialTypes', async () => {
    const deepLink = await verifier.generateRequest(
      ['AgeCredential', 'NameCredential'],
      'https://example.com/verify',
    );
    const url = new URL(deepLink);
    const jwt = decodeURIComponent(url.searchParams.get('request')!);
    const [, encodedPayload] = jwt.split('.');
    const payload = JSON.parse(base64urlDecode(encodedPayload));

    expect(payload.verifierDID).toBe('did:mitch:verifier-liquor-store');
    expect(payload.credentialTypes).toEqual(['AgeCredential', 'NameCredential']);
    expect(payload.callbackURL).toBe('https://example.com/verify');
    expect(payload.challenge).toBeTruthy();
    expect(payload.nonce).toBeTruthy();
    expect(payload.timestamp).toBeGreaterThan(0);
  });

  it('generates unique nonces per request', async () => {
    const link1 = await verifier.generateRequest(['AgeCredential'], 'https://a.com/v');
    const link2 = await verifier.generateRequest(['AgeCredential'], 'https://a.com/v');

    const getNonce = (link: string) => {
      const url = new URL(link);
      const jwt = decodeURIComponent(url.searchParams.get('request')!);
      const [, ep] = jwt.split('.');
      return JSON.parse(base64urlDecode(ep)).nonce;
    };

    expect(getNonce(link1)).not.toBe(getNonce(link2));
  });

  it('throws if not initialized when generating request', async () => {
    const uninit = new VerifierDirectClient('did:mitch:test');
    await expect(
      uninit.generateRequest(['AgeCredential'], 'https://x.com/v'),
    ).rejects.toThrow('Verifier not initialized');
  });

  it('verifyResponse returns true (Phase-0 stub)', async () => {
    const response: VerificationResponse = {
      type: 'ZKProof',
      claim: 'age_over_18',
      proof: '0xABCD',
      timestamp: Date.now(),
      nonce: 'test-nonce',
    };
    const result = await verifier.verifyResponse(response);
    expect(result).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// WalletDirectProtocol
// ---------------------------------------------------------------------------
describe('WalletDirectProtocol', () => {
  let wallet: WalletDirectProtocol;
  let verifier: VerifierDirectClient;

  beforeEach(async () => {
    wallet = new WalletDirectProtocol();
    verifier = new VerifierDirectClient('did:mitch:verifier-test');
    await verifier.initialize();
  });

  it('parses a verifier-generated deep link', async () => {
    const deepLink = await verifier.generateRequest(
      ['AgeCredential'],
      'https://example.com/verify',
    );

    const request = await wallet.parseRequest(deepLink);
    expect(request.verifierDID).toBe('did:mitch:verifier-test');
    expect(request.credentialTypes).toEqual(['AgeCredential']);
    expect(request.callbackURL).toBe('https://example.com/verify');
    expect(request.challenge).toBeTruthy();
    expect(request.nonce).toBeTruthy();
  });

  it('throws for invalid deep link missing request param', async () => {
    await expect(wallet.parseRequest('mitch://present')).rejects.toThrow(
      'Invalid deep-link: missing request parameter',
    );
  });

  it('throws for expired request (>5min old)', async () => {
    // Create a deep link, then parse a modified version with old timestamp
    const deepLink = await verifier.generateRequest(
      ['AgeCredential'],
      'https://example.com/verify',
    );

    const url = new URL(deepLink);
    const jwt = decodeURIComponent(url.searchParams.get('request')!);
    const [header, encodedPayload, sig] = jwt.split('.');
    const payload = JSON.parse(base64urlDecode(encodedPayload));
    payload.timestamp = Date.now() - 400000; // 6+ minutes ago

    const newPayload = base64urlEncode(JSON.stringify(payload));
    const newJwt = `${header}.${newPayload}.${sig}`;
    const newDeepLink = `mitch://present?request=${encodeURIComponent(newJwt)}`;

    await expect(wallet.parseRequest(newDeepLink)).rejects.toThrow('Request expired');
  });

  it('throws for request missing required fields', async () => {
    const payload = { verifierDID: 'did:mitch:test' }; // missing most fields
    const header = base64urlEncode(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
    const body = base64urlEncode(JSON.stringify(payload));
    const jwt = `${header}.${body}.fake-sig`;
    const deepLink = `mitch://present?request=${encodeURIComponent(jwt)}`;

    await expect(wallet.parseRequest(deepLink)).rejects.toThrow('Invalid request: missing');
  });

  it('sendProofToVerifier calls fetch with POST', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ verified: true }),
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch;

    try {
      const response: VerificationResponse = {
        type: 'ZKProof',
        claim: 'age_over_18',
        proof: '0xABCD',
        timestamp: Date.now(),
        nonce: 'n1',
      };

      await wallet.sendProofToVerifier('https://example.com/verify/session-1', response);

      expect(mockFetch).toHaveBeenCalledWith('https://example.com/verify/session-1', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(response),
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('sendProofToVerifier throws on verifier rejection', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch;

    try {
      const response: VerificationResponse = {
        type: 'ZKProof',
        claim: 'age_over_18',
        proof: '0xABCD',
        timestamp: Date.now(),
        nonce: 'n1',
      };

      await expect(
        wallet.sendProofToVerifier('https://example.com/verify', response),
      ).rejects.toThrow('Verifier rejected proof: 403');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ---------------------------------------------------------------------------
// Full round-trip: Verifier -> Wallet -> Verifier
// ---------------------------------------------------------------------------
describe('Verifier-Direct round-trip', () => {
  it('completes a full presentation flow', async () => {
    const verifier = new VerifierDirectClient('did:mitch:verifier-liquor-store');
    await verifier.initialize();

    // Step 1: Verifier creates request
    const deepLink = await verifier.generateRequest(
      ['AgeCredential'],
      'https://liquor-store.com/api/verify',
    );
    expect(deepLink).toContain('mitch://present');

    // Step 2: Wallet parses request
    const wallet = new WalletDirectProtocol();
    const request = await wallet.parseRequest(deepLink);

    expect(request.verifierDID).toBe('did:mitch:verifier-liquor-store');
    expect(request.credentialTypes).toContain('AgeCredential');

    // Step 3: Wallet creates proof
    const proof: VerificationResponse = {
      type: 'ZKProof',
      claim: 'age_over_18',
      proof: '0xPROOF_DATA',
      timestamp: Date.now(),
      nonce: request.nonce,
    };

    // Step 4: Verifier verifies response
    const verified = await verifier.verifyResponse(proof);
    expect(verified).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function base64urlDecode(data: string): string {
  const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  return atob(base64 + padding);
}

function base64urlEncode(data: string): string {
  const bytes = new TextEncoder().encode(data);
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
