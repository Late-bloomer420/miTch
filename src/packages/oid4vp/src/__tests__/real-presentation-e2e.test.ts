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
  createKeyBindingJWT,
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
  it('round-trips a signed clear age with no selected disclosures and rejects a wrong nonce', async () => {
    const issuer = await ecKey();
    const holder = await ecKey();
    const issuerJwt = await issueSDJWTVC(
      {
        iss: 'https://issuer.example',
        vct: 'https://askmi.demo/vct/age-credential',
        cnf: await buildCNFClaim(holder.publicKey),
        age: 24,
        iat: Math.floor(Date.now() / 1000),
      },
      issuer.privateKey
    );
    const { vpToken, disclosedClaims } = await buildSdJwtPresentation(
      `${issuerJwt}~`, ['age'], holder.privateKey,
      { aud: 'did:askmi:verifier', nonce: 'nonce-clear' }
    );

    expect(vpToken.split('~')).toHaveLength(2);
    expect(vpToken.split('~')[0]).toBe(issuerJwt);
    expect(disclosedClaims).toEqual({});
    const verify = (nonce: string, issuerPublicKey: CryptoKey) => validateSDJWTPresentation({
      vpTokenString: vpToken,
      request: makeRequest(nonce),
      issuerPublicKey,
      checkRevocation: false,
      checkTrust: false,
    });
    expect(await verify('nonce-clear', issuer.publicKey)).toEqual({
      ok: true, disclosedClaims: { age: 24 }, errors: [],
    });
    expect((await verify('wrong-nonce', issuer.publicKey)).ok).toBe(false);
    expect((await verify('nonce-clear', (await ecKey()).publicKey)).ok).toBe(false);
  });

  it('rejects an actually supplied empty disclosure even with valid holder binding', async () => {
    const issuer = await ecKey();
    const holder = await ecKey();
    const stored = await issueLikeIssuerMock(issuer, holder.publicKey);
    const presented = `${stored.split('~')[0]}~~`;
    const kb = await createKeyBindingJWT({
      aud: 'did:askmi:verifier', nonce: 'nonce-empty', sdJwtWithDisclosures: presented,
    }, holder.privateKey);
    const result = await validateSDJWTPresentation({
      vpTokenString: `${presented}${kb}`,
      request: makeRequest('nonce-empty'),
      issuerPublicKey: issuer.publicKey,
      checkRevocation: false,
      checkTrust: false,
    });
    expect(result).toEqual({ ok: false, errors: ['Invalid SD-JWT disclosure'] });
  });

  it('rejects an unreferenced disclosure even when a holder binds the full presentation', async () => {
    const issuer = await ecKey();
    const holder = await ecKey();
    const stored = await issueLikeIssuerMock(issuer, holder.publicKey);
    const { disclosures } = await createSDJWTDisclosures({ injected: 'untrusted' });
    const presented = `${stored.split('~')[0]}~${disclosures[0]}~`;
    const kb = await createKeyBindingJWT({ aud: 'did:askmi:verifier', nonce: 'nonce-bad', sdJwtWithDisclosures: presented }, holder.privateKey);
    const result = await validateSDJWTPresentation({
      vpTokenString: `${presented}${kb}`,
      request: makeRequest('nonce-bad'),
      issuerPublicKey: issuer.publicKey,
      checkRevocation: false,
      checkTrust: false,
    });
    expect(result).toEqual({ ok: false, errors: ['Invalid SD-JWT disclosure'] });
  });
  /**
   * Issue a credential whose signed `_sd` references a disclosure for `{ [name]: value }`,
   * with `clearPayload` claims in the clear, then present exactly that one disclosure
   * with a valid KB-JWT. Everything is issuer-signed and holder-bound, so the only reason
   * for rejection is the verifier's name-collision rule.
   */
  async function presentCollidingDisclosure(
    name: string, value: unknown, clearPayload: Record<string, unknown>, nonce: string,
  ) {
    const issuer = await ecKey();
    const holder = await ecKey();
    const { _sd, disclosures } = await createSDJWTDisclosures({ [name]: value });
    const issuerJwt = await issueSDJWTVC(
      {
        iss: 'https://issuer.example',
        vct: 'https://askmi.demo/vct/age-credential',
        cnf: await buildCNFClaim(holder.publicKey),
        iat: Math.floor(Date.now() / 1000),
        ...clearPayload,
        _sd,
      },
      issuer.privateKey
    );
    const presented = `${issuerJwt}~${disclosures[0]}~`;
    const kb = await createKeyBindingJWT(
      { aud: 'did:askmi:verifier', nonce, sdJwtWithDisclosures: presented }, holder.privateKey
    );
    return validateSDJWTPresentation({
      vpTokenString: `${presented}${kb}`,
      request: makeRequest(nonce),
      issuerPublicKey: issuer.publicKey,
      checkRevocation: false,
      checkTrust: false,
    });
  }

  it('rejects an issuer-referenced disclosure that collides with a clear-text claim', async () => {
    // Signed payload carries age: 24 in the clear AND an _sd entry that would reveal age: 99.
    const result = await presentCollidingDisclosure('age', 99, { age: 24 }, 'nonce-collide-clear');
    expect(result).toEqual({ ok: false, errors: ['Invalid SD-JWT disclosure'] });
  });

  it('rejects an issuer-referenced disclosure named like a metadata key', async () => {
    // `nbf` is a metadata key and absent from the clear payload, so only the metadata rule can reject it.
    const result = await presentCollidingDisclosure('nbf', 1, {}, 'nonce-collide-meta');
    expect(result).toEqual({ ok: false, errors: ['Invalid SD-JWT disclosure'] });
  });

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
