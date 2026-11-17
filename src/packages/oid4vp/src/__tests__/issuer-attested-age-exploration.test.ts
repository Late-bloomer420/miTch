/** Synthetic exploration for #97: not an EUDI profile or a ZK proof. */
import { describe, expect, it } from 'vitest';
import {
  buildCNFClaim,
  buildSdJwtPresentation,
  createSDJWTDisclosures,
  issueSDJWTVC,
} from '@askmi/shared-crypto';
import { validateSDJWTPresentation } from '../demo-flow';
import type { AuthorizationRequest } from '../types';

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

describe('synthetic issuer-attested age boolean', () => {
  it('verifies the issuer-attested boolean while withholding age and date of birth', async () => {
    const issuer = await keyPair();
    const holder = await keyPair();
    const { _sd, disclosures } = await createSDJWTDisclosures({
      age_over_18: true,
      age: 24,
      birthdate: '2000-01-01',
    });
    const jwt = await issueSDJWTVC({
      iss: 'https://issuer.example',
      vct: 'https://example.org/synthetic-age-boolean',
      iat: Math.floor(Date.now() / 1000),
      cnf: await buildCNFClaim(holder.publicKey),
      _sd,
    }, issuer.privateKey);
    const request: AuthorizationRequest = {
      response_type: 'vp_token',
      client_id: 'did:example:verifier',
      redirect_uri: 'https://verifier.example/response',
      nonce: 'test-nonce',
      response_mode: 'direct_post',
      presentation_definition: { id: 'synthetic-age', input_descriptors: [] },
    };
    const { vpToken } = await buildSdJwtPresentation(
      `${jwt}~${disclosures.join('~')}~`, ['age_over_18'], holder.privateKey,
      { aud: request.client_id, nonce: request.nonce }
    );
    const verify = (issuerPublicKey: CryptoKey, nonce = request.nonce) =>
      validateSDJWTPresentation({
        vpTokenString: vpToken,
        request: { ...request, nonce },
        issuerPublicKey,
        checkRevocation: false,
        checkTrust: false,
      });

    expect(vpToken.split('~')[0]).toBe(jwt);
    expect(vpToken).not.toContain(disclosures[1]);
    expect(vpToken).not.toContain(disclosures[2]);
    const result = await verify(issuer.publicKey);
    expect(result.ok).toBe(true);
    expect(result.disclosedClaims).toEqual({ age_over_18: true });
    expect((await verify((await keyPair()).publicKey)).ok).toBe(false);
    expect((await verify(issuer.publicKey, 'wrong-nonce')).ok).toBe(false);
  });
});
