/**
 * ADOPT-0b end-to-end: the real chain that unit tests did not cover —
 * an issuer-mock-format SD-JWT VC (ADOPT-0a: _sd disclosures + cnf) is presented
 * by the wallet's real builder (buildSdJwtPresentation, selective disclosure +
 * KB-JWT) and verified by the verifier (validateSDJWTPresentation) against the
 * REAL issuer key. Proves the wallet's new presentation format is accepted and
 * that the requested claim is actually disclosed (regression for the two bugs:
 * verifier ignored disclosures; requested-vs-issued claim-name mismatch).
 */
import { describe, it, expect } from 'vitest';
import {
  issueSDJWTVC,
  createSDJWTDisclosures,
  buildCNFClaim,
  buildSdJwtPresentation,
} from '@askmi/shared-crypto';
import { validateSDJWTPresentation } from '../demo-flow';
import type { AuthorizationRequest } from '../types';

async function ecKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

function makeRequest(nonce: string): AuthorizationRequest {
  return {
    response_type: 'vp_token',
    client_id: 'did:askmi:verifier',
    redirect_uri: 'https://verifier.example/oid4vp-present',
    nonce,
    presentation_definition: { id: 'p', input_descriptors: [] },
    response_mode: 'direct_post',
  } as unknown as AuthorizationRequest;
}

/** Issue a credential the way issuer-mock (ADOPT-0a) does. */
async function issueLikeIssuerMock(issuer: CryptoKeyPair, holderPub: CryptoKey): Promise<string> {
  const { _sd, disclosures } = await createSDJWTDisclosures({ age: 24, dateOfBirth: '2000-01-01' });
  const issuerJwt = await issueSDJWTVC(
    {
      iss: 'did:web:localhost%3A3005',
      vct: 'https://askmi.demo/vct/age-credential',
      cnf: await buildCNFClaim(holderPub),
      _sd,
      iat: Math.floor(Date.now() / 1000),
    },
    issuer.privateKey
  );
  return `${issuerJwt}~${disclosures.join('~')}~`;
}

describe('ADOPT-0b real presentation e2e', () => {
  it('discloses only the requested claim (age) and verifies against the real issuer key', async () => {
    const issuer = await ecKey();
    const holder = await ecKey();
    const stored = await issueLikeIssuerMock(issuer, holder.publicKey);

    // Wallet presents, selectively disclosing only $.age (what the liquor request asks).
    const { vpToken } = await buildSdJwtPresentation(stored, ['age'], holder.privateKey, {
      aud: 'did:askmi:verifier',
      nonce: 'nonce-1',
    });

    const result = await validateSDJWTPresentation({
      vpTokenString: vpToken,
      request: makeRequest('nonce-1'),
      issuerPublicKey: issuer.publicKey,
      checkRevocation: false,
      checkTrust: false,
    });

    expect(result.ok).toBe(true);
    expect(result.disclosedClaims).toEqual({ age: 24 }); // requested claim IS disclosed
    expect(result.disclosedClaims).not.toHaveProperty('dateOfBirth'); // withheld (selective disclosure)
  });

  it('fails verification against a swapped (wrong) issuer key', async () => {
    const issuer = await ecKey();
    const holder = await ecKey();
    const stored = await issueLikeIssuerMock(issuer, holder.publicKey);
    const { vpToken } = await buildSdJwtPresentation(stored, ['age'], holder.privateKey, {
      aud: 'did:askmi:verifier',
      nonce: 'nonce-2',
    });

    const attacker = await ecKey();
    const result = await validateSDJWTPresentation({
      vpTokenString: vpToken,
      request: makeRequest('nonce-2'),
      issuerPublicKey: attacker.publicKey, // wrong key → signature must not verify
      checkRevocation: false,
      checkTrust: false,
    });

    expect(result.ok).toBe(false);
  });
});
