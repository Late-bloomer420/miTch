/**
 * Test-only software authenticator that produces real WebAuthn assertions:
 * ES256 (P-256) key, COSE-encoded public key, authenticatorData with the real
 * rpIdHash, and a DER ECDSA signature over authenticatorData || SHA-256(clientDataJSON).
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

export interface SoftAuthenticator {
  credentialID: Buffer;
  credentialPublicKey: Buffer;
  assert(opts: {
    challenge: string;
    origin: string;
    rpID: string;
    counter: number;
    flags?: number;
    type?: string;
  }): {
    id: string;
    rawId: string;
    response: { clientDataJSON: string; authenticatorData: string; signature: string };
    type: 'public-key';
  };
}

export function createSoftAuthenticator(id = 'soft-credential'): SoftAuthenticator {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const cose = new Map<number, number | Uint8Array>([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ]);
  const credentialID = Buffer.from(id);
  return {
    credentialID,
    credentialPublicKey: Buffer.from(isoCBOR.encode(cose)),
    assert({ challenge, origin, rpID, counter, flags = 0x05, type = 'webauthn.get' }) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge, origin }));
      const counterBuf = Buffer.alloc(4);
      counterBuf.writeUInt32BE(counter, 0);
      const authData = Buffer.concat([
        createHash('sha256').update(rpID).digest(),
        Buffer.from([flags]),
        counterBuf,
      ]);
      const signature = sign(
        'sha256',
        Buffer.concat([authData, createHash('sha256').update(clientDataJSON).digest()]),
        privateKey
      );
      return {
        id: credentialID.toString('base64url'),
        rawId: credentialID.toString('base64url'),
        response: {
          clientDataJSON: clientDataJSON.toString('base64url'),
          authenticatorData: authData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
        type: 'public-key',
      };
    },
  };
}
