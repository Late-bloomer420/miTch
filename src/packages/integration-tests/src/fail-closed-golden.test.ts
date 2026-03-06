/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * @module fail-closed-golden
 *
 * 🔒 FAIL-CLOSED GOLDEN REGRESSION GATE
 *
 * These tests enforce the 3 Golden Invariants that must NEVER be violated.
 * They are merge-blocking in CI. If any test here fails, the build fails.
 *
 * Background: A critical bug was found where StatusList fetch failure returned
 * ALLOW instead of DENY. These tests ensure that class of bug can never return.
 *
 * Golden Invariants:
 *   1. Unknown verifier / DID resolution fails → DENY
 *   2. Revocation status unknown/unreachable → DENY (for configured risk layers)
 *   3. Policy ambiguity / purpose mismatch → DENY or PROMPT, never ALLOW
 */

import { describe, it, expect, vi } from 'vitest';
import { StatusListRevocationChecker } from '@mitch/revocation-statuslist';
import type { StatusListEntry, StatusListCredential } from '@mitch/revocation-statuslist';
import { DIDResolver, DIDResolutionError } from '@mitch/shared-crypto';
import { PolicyEngine, ReasonCode } from '@mitch/policy-engine';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';
import type { EvaluationContext } from '@mitch/policy-engine';

// ─── Helpers ──────────────────────────────────────────────────────────────

function makeEncodedList(revokedIndices: number[], byteCount = 4): string {
  const bytes = new Uint8Array(byteCount);
  for (const idx of revokedIndices) {
    const byteIndex = Math.floor(idx / 8);
    const bitIndex = idx % 8;
    if (byteIndex < byteCount) {
      bytes[byteIndex] |= 1 << (7 - bitIndex);
    }
  }
  return btoa(String.fromCharCode(...bytes));
}

function makeStatusListCredential(revokedIndices: number[] = []): StatusListCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'https://example.com/status-list/1',
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: 'did:example:issuer',
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'https://example.com/status-list/1#list',
      type: 'StatusList2021',
      statusPurpose: 'revocation',
      encodedList: makeEncodedList(revokedIndices),
    },
  };
}

function makeEntry(index = 0, url = 'https://example.com/status-list/1'): StatusListEntry {
  return {
    id: `${url}#${index}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential: url,
  };
}

function mockFetchFail(): typeof fetch {
  return vi.fn().mockRejectedValue(new Error('Network error')) as any;
}

function mockFetchHttp500(): typeof fetch {
  return vi.fn().mockResolvedValue({ ok: false, status: 500, statusText: 'Internal Server Error' }) as any;
}

function mockFetchMalformedJson(): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ garbage: true }),
  }) as any;
}

function mockFetchHangs(): typeof fetch {
  return vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
    return new Promise((_resolve, reject) => {
      if (init?.signal) {
        init.signal.addEventListener('abort', () => reject(new Error('Aborted')));
      }
      // Never resolves on its own — waits for abort signal
    });
  }) as any;
}

const BASE_CONTEXT: EvaluationContext = {
  timestamp: Date.now(),
  userDID: 'did:example:user',
};

const TRUSTED_ISSUER_DID = 'did:example:trusted-issuer';

function makePolicy(overrides: Partial<PolicyManifest> = {}): PolicyManifest {
  return {
    version: '1.0.0',
    rules: [{
      id: 'known-verifier-rule',
      verifierPattern: 'did:example:known-verifier',
      allowedClaims: ['age_over_18'],
      provenClaims: ['age_over_18'],
      requiresTrustedIssuer: true,
      maxCredentialAgeDays: 365,
      priority: 1,
      requiresUserConsent: false,
    }],
    trustedIssuers: [{
      did: TRUSTED_ISSUER_DID,
      credentialTypes: ['AgeCredential'],
      name: 'Test Issuer',
    }],
    globalSettings: {
      blockUnknownVerifiers: true,
      requireConsentForAll: false,
    },
    ...overrides,
  } as PolicyManifest;
}

function makeRequest(verifierId: string, claims: string[] = ['age_over_18']): VerifierRequest {
  return {
    verifierId,
    requestedClaims: claims,
    requestedProvenClaims: [],
    requirements: [{
      credentialType: 'AgeCredential',
      requestedClaims: claims,
      requestedProvenClaims: [],
    }],
    nonce: 'test-nonce-' + Date.now(),
  } as VerifierRequest;
}

function makeCredential(): StoredCredentialMetadata {
  return {
    id: 'cred-1',
    type: ['AgeCredential'],
    issuer: TRUSTED_ISSUER_DID,
    issuedAt: new Date(Date.now() - 86400000).toISOString(), // yesterday
    expiresAt: new Date(Date.now() + 86400000 * 365).toISOString(),
    claims: ['age_over_18'],
  } as StoredCredentialMetadata;
}

// ═══════════════════════════════════════════════════════════════════════════
// GOLDEN INVARIANT 1: Unknown verifier / DID resolution fails → DENY
// ═══════════════════════════════════════════════════════════════════════════

describe('🔒 GOLDEN INVARIANT 1: Unknown verifier / DID resolution fails → DENY', () => {

  describe('DID Resolution failures', () => {
    it('network error during DID resolution → throws DIDResolutionError', async () => {
      const resolver = new DIDResolver({
        fetchFn: mockFetchFail(),
        allowMockFallback: false,
      });

      await expect(resolver.resolve('did:web:unreachable.example.com'))
        .rejects.toThrow(DIDResolutionError);
    });

    it('HTTP 500 from DID resolver → throws DIDResolutionError', async () => {
      const resolver = new DIDResolver({
        fetchFn: mockFetchHttp500(),
        allowMockFallback: false,
      });

      await expect(resolver.resolve('did:web:broken.example.com'))
        .rejects.toThrow(DIDResolutionError);
    });

    it('timeout during DID resolution → throws DIDResolutionError', async () => {
      const resolver = new DIDResolver({
        fetchFn: mockFetchHangs(),
        fetchTimeoutMs: 100,
        allowMockFallback: false,
      });

      await expect(resolver.resolve('did:web:slow.example.com'))
        .rejects.toThrow(DIDResolutionError);
    }, 10_000);

    it('unsupported DID method without mock fallback → throws DIDResolutionError', async () => {
      const resolver = new DIDResolver({ allowMockFallback: false });

      await expect(resolver.resolve('did:unknown:something'))
        .rejects.toThrow(DIDResolutionError);
    });

    it('empty/null DID → throws DIDResolutionError', async () => {
      const resolver = new DIDResolver({ allowMockFallback: false });

      await expect(resolver.resolve('')).rejects.toThrow(DIDResolutionError);
    });

    it('malformed DID document (missing id) → throws DIDResolutionError', async () => {
      const resolver = new DIDResolver({
        fetchFn: vi.fn().mockResolvedValue({
          ok: true,
          json: () => Promise.resolve({ '@context': ['https://www.w3.org/ns/did/v1'] }),
        }) as any,
        allowMockFallback: false,
      });

      await expect(resolver.resolve('did:web:malformed.example.com'))
        .rejects.toThrow(DIDResolutionError);
    });
  });

  describe('Unknown verifier in policy engine', () => {
    it('unknown verifier with blockUnknownVerifiers=true → DENY', async () => {
      const engine = new PolicyEngine();
      const result = await engine.evaluate(
        makeRequest('did:example:unknown-verifier'),
        BASE_CONTEXT,
        [makeCredential()],
        makePolicy(),
      );

      expect(result.verdict).toBe('DENY');
      expect(result.reasonCodes).toContain(ReasonCode.UNKNOWN_VERIFIER);
    });

    it('unknown verifier with no matching rule → DENY (never ALLOW)', async () => {
      const engine = new PolicyEngine();
      const policy = makePolicy({
        globalSettings: { blockUnknownVerifiers: false },
      });

      const result = await engine.evaluate(
        makeRequest('did:example:no-rule-matches'),
        BASE_CONTEXT,
        [makeCredential()],
        policy,
      );

      expect(result.verdict).toBe('DENY');
      expect(result.verdict).not.toBe('ALLOW');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// GOLDEN INVARIANT 2: Revocation status unknown/unreachable → DENY
// ═══════════════════════════════════════════════════════════════════════════

describe('🔒 GOLDEN INVARIANT 2: Revocation status unknown/unreachable → DENY', () => {

  describe('StatusList fetch failures (high-risk)', () => {
    it('network error → DENY, never ALLOW', async () => {
      const checker = new StatusListRevocationChecker({ fetchFn: mockFetchFail() });
      const result = await checker.checkRevocation(makeEntry(), 'high');

      expect(result.decision).toBe('DENY');
      expect(result.decision).not.toBe('ALLOW');
      expect(result.denyCode).toBe('DENY_STATUS_SOURCE_UNAVAILABLE');
    });

    it('HTTP 500 → DENY, never ALLOW', async () => {
      const checker = new StatusListRevocationChecker({ fetchFn: mockFetchHttp500() });
      const result = await checker.checkRevocation(makeEntry(), 'high');

      expect(result.decision).toBe('DENY');
      expect(result.decision).not.toBe('ALLOW');
    });

    it('timeout → DENY, never ALLOW', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchHangs(),
        fetchTimeoutMs: 100,
      });
      const result = await checker.checkRevocation(makeEntry(), 'high');

      expect(result.decision).toBe('DENY');
      expect(result.decision).not.toBe('ALLOW');
    }, 10_000);

    it('malformed response (missing encodedList) → DENY', async () => {
      const checker = new StatusListRevocationChecker({ fetchFn: mockFetchMalformedJson() });
      const result = await checker.checkRevocation(makeEntry(), 'high');

      expect(result.decision).toBe('DENY');
      expect(result.decision).not.toBe('ALLOW');
    });
  });

  describe('StatusList fetch failures (low-risk, no cache)', () => {
    it('network error with no cache → DENY', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchFail(),
        offlineGraceMsLowRisk: 60_000,
      });
      const result = await checker.checkRevocation(makeEntry(), 'low');

      expect(result.decision).toBe('DENY');
      expect(result.decision).not.toBe('ALLOW');
    });
  });

  describe('StatusList fetch failures (low-risk, stale cache beyond grace)', () => {
    it('beyond grace period → DENY', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: mockFetchFail(),
        cacheTtlMs: 1,
        offlineGraceMsLowRisk: 1, // instant expiry
      });

      // No cache primed, fetch fails
      const result = await checker.checkRevocation(makeEntry(), 'low');
      expect(result.decision).toBe('DENY');
    });
  });

  describe('Invalid status list index → DENY', () => {
    it('index out of range → DENY', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: vi.fn().mockResolvedValue({
          ok: true,
          json: () => Promise.resolve(makeStatusListCredential()),
        }) as any,
      });

      const result = await checker.checkRevocation(makeEntry(9999), 'high');
      expect(result.decision).toBe('DENY');
    });

    it('negative index → DENY', async () => {
      const checker = new StatusListRevocationChecker({
        fetchFn: vi.fn().mockResolvedValue({
          ok: true,
          json: () => Promise.resolve(makeStatusListCredential()),
        }) as any,
      });

      const entry = makeEntry(0);
      entry.statusListIndex = '-1';
      const result = await checker.checkRevocation(entry, 'high');
      expect(result.decision).toBe('DENY');
    });
  });

  // ─── REGRESSION: The exact bug we found ─────────────────────────────────
  describe('🐛 REGRESSION: StatusList fetch failure must return DENY, never ALLOW', () => {
    /**
     * This is the specific regression test for the bug found on 2026-03-03.
     * The revocation checker was returning ALLOW when the StatusList fetch failed.
     * This must NEVER happen again.
     */

    const FAILURE_MODES: Array<{ name: string; makeFetchFn: () => typeof fetch }> = [
      { name: 'network error', makeFetchFn: mockFetchFail },
      { name: 'HTTP 500', makeFetchFn: mockFetchHttp500 },
      { name: 'malformed JSON', makeFetchFn: mockFetchMalformedJson },
      { name: 'connection hang/timeout', makeFetchFn: mockFetchHangs },
    ];

    for (const { name, makeFetchFn } of FAILURE_MODES) {
      it(`${name} → decision is DENY (never ALLOW) [high-risk]`, async () => {
        const checker = new StatusListRevocationChecker({
          fetchFn: makeFetchFn(),
          fetchTimeoutMs: 200,
        });

        const result = await checker.checkRevocation(makeEntry(), 'high');

        // THE GOLDEN ASSERTION: This must NEVER be ALLOW
        expect(result.decision).not.toBe('ALLOW');
        expect(result.decision).toBe('DENY');
      }, 10_000);

      it(`${name} → decision is DENY (never ALLOW) [low-risk, no cache]`, async () => {
        const checker = new StatusListRevocationChecker({
          fetchFn: makeFetchFn(),
          fetchTimeoutMs: 200,
        });

        const result = await checker.checkRevocation(makeEntry(), 'low');

        // THE GOLDEN ASSERTION: Without cache, even low-risk must DENY
        expect(result.decision).not.toBe('ALLOW');
        expect(result.decision).toBe('DENY');
      }, 10_000);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// GOLDEN INVARIANT 3: Policy ambiguity / purpose mismatch → DENY or PROMPT, never ALLOW
// ═══════════════════════════════════════════════════════════════════════════

describe('🔒 GOLDEN INVARIANT 3: Policy ambiguity / purpose mismatch → DENY or PROMPT, never ALLOW', () => {

  describe('Claim not in allowed list', () => {
    it('requesting disallowed claim → DENY', async () => {
      const engine = new PolicyEngine();
      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier', ['social_security_number']),
        BASE_CONTEXT,
        [makeCredential()],
        makePolicy(),
      );

      expect(result.verdict).toBe('DENY');
      expect(result.verdict).not.toBe('ALLOW');
    });
  });

  describe('Explicitly denied claims', () => {
    it('claim in deniedClaims → DENY', async () => {
      const engine = new PolicyEngine();
      const policy = makePolicy();
      policy.rules[0].deniedClaims = ['age_over_18'];

      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [makeCredential()],
        policy,
      );

      expect(result.verdict).toBe('DENY');
      expect(result.reasonCodes).toContain(ReasonCode.CLAIM_NOT_ALLOWED);
    });
  });

  describe('No suitable credential', () => {
    it('no matching credential → DENY', async () => {
      const engine = new PolicyEngine();
      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [], // empty wallet
        makePolicy(),
      );

      expect(result.verdict).toBe('DENY');
      expect(result.verdict).not.toBe('ALLOW');
    });
  });

  describe('Untrusted issuer', () => {
    it('credential from untrusted issuer → DENY', async () => {
      const engine = new PolicyEngine();
      const cred = makeCredential();
      cred.issuer = 'did:example:evil-issuer';

      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [cred],
        makePolicy(),
      );

      expect(result.verdict).toBe('DENY');
      expect(result.verdict).not.toBe('ALLOW');
    });
  });

  describe('Consent-required scenarios → PROMPT (not ALLOW)', () => {
    it('requiresUserConsent=true → PROMPT', async () => {
      const engine = new PolicyEngine();
      const policy = makePolicy();
      policy.rules[0].requiresUserConsent = true;

      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [makeCredential()],
        policy,
      );

      expect(result.verdict).toBe('PROMPT');
      expect(result.verdict).not.toBe('ALLOW');
    });

    it('requireConsentForAll=true → PROMPT', async () => {
      const engine = new PolicyEngine();
      const policy = makePolicy({
        globalSettings: {
          blockUnknownVerifiers: true,
          requireConsentForAll: true,
        },
      });

      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [makeCredential()],
        policy,
      );

      expect(result.verdict).toBe('PROMPT');
    });
  });

  describe('Expired credential', () => {
    it('expired credential → DENY', async () => {
      const engine = new PolicyEngine();
      const cred = makeCredential();
      cred.expiresAt = new Date(Date.now() - 86400000).toISOString(); // expired yesterday

      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [cred],
        makePolicy(),
      );

      expect(result.verdict).toBe('DENY');
      expect(result.verdict).not.toBe('ALLOW');
    });
  });

  describe('Meta-invariant: verdict is always ALLOW | DENY | PROMPT', () => {
    it('valid request → verdict is one of the three legal values', async () => {
      const engine = new PolicyEngine();
      const result = await engine.evaluate(
        makeRequest('did:example:known-verifier'),
        BASE_CONTEXT,
        [makeCredential()],
        makePolicy(),
      );

      expect(['ALLOW', 'DENY', 'PROMPT']).toContain(result.verdict);
    });
  });
});
