/**
 * Batch Credential Issuance with Holder Binding (Proof-Randomization, Increment 2 / C2)
 *
 * Wallet-generates / issuer-binds: the wallet mints N non-extractable holder
 * keypairs locally and sends only the PUBLIC halves (JWKs). For each, the issuer
 * binds that public key into a distinct credential — as a `did:jwk` subject id
 * AND a `cnf` block — then signs. Private keys never cross the wire.
 *
 * Honesty boundary: this delivers a distinct holder binding + distinct issuer
 * signature per member (the observable the sprint's acceptance criterion names).
 * Presentation-time Key-Binding-JWT verification is the C1 follow-up.
 */

import { signVC } from '@askmi/shared-crypto';

/** A public-key holder binding (only the public JWK is ever transmitted). */
export interface HolderBindingJwk {
  type: 'jwk';
  jwk: JsonWebKey;
}

/** One element of a batch issuance request. */
export interface BatchCredentialRequestItem {
  credential_definition: { type: string[] };
  holder_binding: HolderBindingJwk;
}

/** The batch issuance request body. */
export interface BatchIssuanceRequest {
  requests: BatchCredentialRequestItem[];
}

/** Raised on a malformed batch — the whole batch is rejected (fail-closed). */
export class BatchValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BatchValidationError';
  }
}

/**
 * Encode a PUBLIC JWK as a `did:jwk` identifier (draft did:jwk method):
 * `did:jwk:` + base64url(utf8(JSON(jwk))). Any private `d` is stripped
 * defensively so a private component can never be embedded as a subject id.
 */
export function didJwkFromJwk(jwk: JsonWebKey): string {
  const pub: JsonWebKey = { ...jwk };
  delete (pub as Record<string, unknown>).d;
  const b64url = Buffer.from(JSON.stringify(pub), 'utf8').toString('base64url');
  return `did:jwk:${b64url}`;
}

/** Strip any private component from a JWK, returning only public members. */
function publicJwkOnly(jwk: JsonWebKey): JsonWebKey {
  const pub: JsonWebKey = { ...jwk };
  delete (pub as Record<string, unknown>).d;
  return pub;
}

/**
 * Validate a raw request body into a BatchIssuanceRequest. Fail-closed: a
 * missing/empty `requests` array, or any item lacking a `holder_binding.jwk`
 * with EC x/y coordinates, rejects the ENTIRE batch (atomic, all-or-nothing).
 */
export function assertValidBatch(body: unknown): BatchIssuanceRequest {
  if (!body || typeof body !== 'object') {
    throw new BatchValidationError('Body must be an object.');
  }
  const requests = (body as { requests?: unknown }).requests;
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new BatchValidationError('`requests` must be a non-empty array.');
  }
  requests.forEach((item, i) => {
    const hb = (item as BatchCredentialRequestItem | undefined)?.holder_binding;
    const jwk = hb?.jwk;
    if (!hb || hb.type !== 'jwk' || !jwk) {
      throw new BatchValidationError(`requests[${i}]: holder_binding.jwk (type 'jwk') is required.`);
    }
    if (jwk.kty !== 'EC' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
      throw new BatchValidationError(`requests[${i}]: holder_binding.jwk must be an EC public key (kty/x/y).`);
    }
    if ('d' in jwk) {
      throw new BatchValidationError(`requests[${i}]: holder_binding.jwk must not contain a private 'd' component.`);
    }
  });
  return { requests: requests as BatchCredentialRequestItem[] };
}

/**
 * Issue one signed AgeCredential JWT per request, each bound to its holder's
 * public key (distinct `did:jwk` subject + `cnf`). Returns the JWTs in the SAME
 * order as the input requests so the wallet can map each back to its private key.
 */
export async function issueAgeCredentialBatch(
  req: BatchIssuanceRequest,
  issuerPrivateKey: CryptoKey,
  issuerDid: string,
  now: Date = new Date()
): Promise<string[]> {
  const jwts: string[] = [];
  for (const item of req.requests) {
    const holderPublicJwk = publicJwkOnly(item.holder_binding.jwk);
    const subjectDid = didJwkFromJwk(holderPublicJwk);

    const vcPayload = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://mitch.example/contexts/age/v1',
      ],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: item.credential_definition.type,
      issuer: { id: issuerDid, name: 'State Liquor Authority' },
      issuanceDate: now.toISOString(),
      // Holder binding: public key carried both as subject id (did:jwk) and cnf.
      cnf: { jwk: holderPublicJwk },
      credentialSubject: {
        id: subjectDid,
        dateOfBirth: '1990-01-01',
        isOver18: true,
      },
    };

    const signed = await signVC(vcPayload as never, issuerPrivateKey);
    if (!signed.proof?.jwt) {
      throw new Error('Signing failed: no JWT produced.');
    }
    jwts.push(signed.proof.jwt);
  }
  return jwts;
}
