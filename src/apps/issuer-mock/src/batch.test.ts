/**
 * Batch issuance + holder binding (Proof-Randomization Increment 2 / C2).
 *
 * Acceptance: batch-issued credentials carry DISTINCT holder fingerprints
 * (different `credentialSubject.id` did:jwk + `cnf`) and DISTINCT issuer
 * signatures, in request order, and the batch is fail-closed on bad input.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair } from '@askmi/shared-crypto';
import {
  assertValidBatch,
  didJwkFromJwk,
  issueAgeCredentialBatch,
  BatchValidationError,
  type BatchIssuanceRequest,
} from './batch';

let issuerPrivateKey: CryptoKey;
const ISSUER_DID = 'did:web:localhost%3A3005';

async function freshPublicJwk(): Promise<JsonWebKey> {
  const kp = await generateKeyPair();
  return crypto.subtle.exportKey('jwk', kp.publicKey);
}

function decodeVc(jwt: string): Record<string, unknown> {
  const payload = JSON.parse(
    Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8')
  ) as { vc: Record<string, unknown> };
  return payload.vc;
}

beforeAll(async () => {
  issuerPrivateKey = (await generateKeyPair()).privateKey;
});

describe('didJwkFromJwk', () => {
  it('produces a did:jwk and strips any private component', () => {
    const did = didJwkFromJwk({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB', d: 'SECRET' } as JsonWebKey);
    expect(did.startsWith('did:jwk:')).toBe(true);
    const decoded = JSON.parse(Buffer.from(did.slice('did:jwk:'.length), 'base64url').toString('utf8'));
    expect(decoded.d).toBeUndefined();
    expect(decoded.x).toBe('AA');
  });
});

describe('assertValidBatch (fail-closed)', () => {
  it('rejects an empty or missing requests array', () => {
    expect(() => assertValidBatch({})).toThrow(BatchValidationError);
    expect(() => assertValidBatch({ requests: [] })).toThrow(BatchValidationError);
  });

  it('rejects an item missing holder_binding.jwk', () => {
    expect(() =>
      assertValidBatch({ requests: [{ credential_definition: { type: ['AgeCredential'] } }] })
    ).toThrow(BatchValidationError);
  });

  it('rejects a JWK carrying a private d component', () => {
    expect(() =>
      assertValidBatch({
        requests: [
          {
            credential_definition: { type: ['AgeCredential'] },
            holder_binding: { type: 'jwk', jwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB', d: 'X' } },
          },
        ],
      })
    ).toThrow(BatchValidationError);
  });
});

describe('issueAgeCredentialBatch', () => {
  it('issues distinct fingerprints + distinct signatures in request order', async () => {
    const jwkA = await freshPublicJwk();
    const jwkB = await freshPublicJwk();
    const req: BatchIssuanceRequest = {
      requests: [jwkA, jwkB].map((jwk) => ({
        credential_definition: { type: ['VerifiableCredential', 'AgeCredential'] },
        holder_binding: { type: 'jwk', jwk },
      })),
    };

    const jwts = await issueAgeCredentialBatch(req, issuerPrivateKey, ISSUER_DID);
    expect(jwts).toHaveLength(2);

    const vcA = decodeVc(jwts[0]);
    const vcB = decodeVc(jwts[1]);

    // Distinct holder fingerprints (subject id + cnf)
    const subA = (vcA.credentialSubject as { id: string }).id;
    const subB = (vcB.credentialSubject as { id: string }).id;
    expect(subA).not.toBe(subB);
    expect(subA).toBe(didJwkFromJwk(jwkA)); // order preserved
    expect(subB).toBe(didJwkFromJwk(jwkB));
    expect((vcA.cnf as { jwk: JsonWebKey }).jwk.x).toBe(jwkA.x);
    expect((vcB.cnf as { jwk: JsonWebKey }).jwk.x).toBe(jwkB.x);

    // Distinct issuer signatures
    const sigA = jwts[0].split('.')[2];
    const sigB = jwts[1].split('.')[2];
    expect(sigA).not.toBe(sigB);

    // cnf must never leak a private component
    expect((vcA.cnf as { jwk: JsonWebKey }).jwk).not.toHaveProperty('d');
  });

  it('issues a single-member batch', async () => {
    const jwk = await freshPublicJwk();
    const jwts = await issueAgeCredentialBatch(
      { requests: [{ credential_definition: { type: ['AgeCredential'] }, holder_binding: { type: 'jwk', jwk } }] },
      issuerPrivateKey,
      ISSUER_DID
    );
    expect(jwts).toHaveLength(1);
    expect((decodeVc(jwts[0]).credentialSubject as { id: string }).id).toBe(didJwkFromJwk(jwk));
  });
});
