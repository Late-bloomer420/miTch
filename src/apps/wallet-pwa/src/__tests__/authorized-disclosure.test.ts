// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
vi.mock('../runtime', () => ({
  isDemoRuntime: true,
  walletDatabaseName: 'askmi_api02_test',
  holderDatabaseName: 'askmi_api02_holder_test',
  identityUserHandle: 'AskMI-demo-identity-key-v1',
}));
import {
  buildCNFClaim,
  buildSdJwtPresentation,
  createSDJWTDisclosures,
  issueSDJWTVC,
} from '@askmi/shared-crypto';
import { WalletService } from '../services/WalletService';
import { authorizedDisclosureClaims } from '../utils/authorized-disclosure';

const ES256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;

function decodeDisclosureNames(vpToken: string): string[] {
  return vpToken
    .split('~')
    .slice(1)
    .filter((s) => s.length > 0 && !s.includes('.'))
    .map((d) => {
      const json = atob(d.replace(/-/g, '+').replace(/_/g, '/'));
      return (JSON.parse(json) as [string, string, unknown])[1];
    });
}

describe('API-02: presentation discloses only policy-authorized claims', () => {
  it('fails closed without a capsule, on DENY and on an empty authorization', () => {
    expect(authorizedDisclosureClaims(null, ['age'])).toEqual([]);
    expect(authorizedDisclosureClaims(undefined, ['age'])).toEqual([]);
    expect(
      authorizedDisclosureClaims(
        {
          verdict: 'DENY',
          authorized_requirements: [
            {
              credential_type: 'AgeCredential',
              allowed_claims: ['age'],
              proven_claims: [],
              selected_credential_id: 'c1',
              issuer_trust_refs: [],
            },
          ],
        },
        ['age']
      )
    ).toEqual([]);
    expect(
      authorizedDisclosureClaims({ verdict: 'ALLOW', authorized_requirements: [] }, ['age'])
    ).toEqual([]);
  });

  it('never adds claims the verifier did not request', () => {
    expect(
      authorizedDisclosureClaims(
        {
          verdict: 'ALLOW',
          authorized_requirements: [
            {
              credential_type: 'AgeCredential',
              allowed_claims: ['age', 'isOver18'],
              proven_claims: [],
              selected_credential_id: 'c1',
              issuer_trust_refs: [],
            },
          ],
        },
        ['age']
      )
    ).toEqual(['age']);
  });

  it('real policy engine + real SD-JWT: an over-asking verifier receives only the authorized claim', async () => {
    // 1. Real WalletService / PolicyEngine with the shipped demo policy (no evaluateRequest mock).
    const wallet = new WalletService();
    await wallet.initialize('test-pin', 'api02-test');
    const verifierRequested = ['age', 'isOver18'];
    const result = await wallet.evaluateRequest(
      {
        verifierId: 'did:askmi:verifier-liquor-store',
        requestedClaims: verifierRequested,
        requestedProvenClaims: [],
        origin: 'http://localhost:3104',
        nonce: crypto.randomUUID(),
      },
      { timestamp: Date.now(), userDID: 'did:example:test' }
    );
    expect(result.verdict).not.toBe('DENY');
    const authorized = authorizedDisclosureClaims(result.decisionCapsule, verifierRequested);
    expect(authorized).toEqual(['age']);

    // 2. Real issuer-signed SD-JWT VC with three disclosable claims.
    const issuer = await crypto.subtle.generateKey(ES256, true, ['sign', 'verify']);
    const holder = await crypto.subtle.generateKey(ES256, true, ['sign', 'verify']);
    const { _sd, disclosures } = await createSDJWTDisclosures({
      age: 24,
      dateOfBirth: '2000-01-01',
      isOver18: true,
    });
    const issuerJwt = await issueSDJWTVC(
      {
        iss: 'did:web:localhost%3A3005',
        vct: 'https://askmi.demo/vct/age-credential',
        iat: Math.floor(Date.now() / 1000),
        cnf: await buildCNFClaim(holder.publicKey),
        _sd,
      },
      issuer.privateKey
    );
    const stored = `${issuerJwt}~${disclosures.join('~')}~`;

    // 3. The pre-fix code passed `verifierRequested` here; the fix passes `authorized`.
    const presented = await buildSdJwtPresentation(stored, authorized, holder.privateKey, {
      aud: 'did:askmi:verifier-liquor-store',
      nonce: 'n-1',
    });
    expect(Object.keys(presented.disclosedClaims)).toEqual(['age']);
    expect(decodeDisclosureNames(presented.vpToken)).toEqual(['age']);

    // Counter-check: the raw verifier request would have leaked isOver18.
    const overAsk = await buildSdJwtPresentation(stored, verifierRequested, holder.privateKey, {
      aud: 'did:askmi:verifier-liquor-store',
      nonce: 'n-2',
    });
    expect(decodeDisclosureNames(overAsk.vpToken).sort()).toEqual(['age', 'isOver18']);
  });
});
