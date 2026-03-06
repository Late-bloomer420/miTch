/**
 * @module @mitch/shared-crypto/signing
 * 
 * Digital Signature Utilities for Verifiable Credentials
 * 
 * Provides signing and verification of VCs using:
 * - JWT-based proofs (JwtProof2020)
 * - ECDSA P-256 with SHA-256
 * - Raw data signing for audit logs and capsules
 * 
 * ## Usage
 * - `signVC()`: Sign a VC with issuer's private key
 * - `verifyVC()`: Verify a signed VC against public key
 * - `signData()`: Sign arbitrary string data
 * - `verifyData()`: Verify signature on string data
 */

import { SignJWT, jwtVerify, importJWK } from 'jose';
import type {
    VerifiableCredential,
    Proof,
} from '@mitch/shared-types';

/**
 * Sign a Verifiable Credential (VC) with a private ECDSA key.
 * The function returns the VC with an attached JWT proof (type `JwtProof2020`).
 *
 * @param vc   VC without a `proof` field
 * @param privateKey CryptoKey (ECDSA, non‑extractable)
 */
export async function signVC<T = Record<string, unknown>>(
    vc: Omit<VerifiableCredential<T>, 'proof'>,
    privateKey: CryptoKey
): Promise<VerifiableCredential<T> & { proof: Proof }> {
    // Generate JWT (JWS) using the private key directly (no export needed for 'jose')
    const jwt = await new SignJWT({ vc })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .setIssuedAt()
        .setIssuer(typeof vc.issuer === 'object' && vc.issuer !== null ? (vc.issuer as { id: string }).id : (vc.issuer as string))
        .setSubject(vc.credentialSubject.id)
        .sign(privateKey);

    const proof: Proof = {
        type: 'JwtProof2020',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${vc.issuer}#key-1`,
        jwt,
    };

    return { ...vc, proof } as VerifiableCredential<T> & { proof: Proof };
}

/**
 * Verify a signed VC that contains a JWT proof.
 * Returns the original VC payload if verification succeeds.
 *
 * @param vc   VC with a `proof.jwt`
 * @param publicKey CryptoKey (ECDSA) or JWK Uint8Array representation
 */
export async function verifyVC<T = Record<string, unknown>>(
    vc: VerifiableCredential<T> & { proof: Proof },
    publicKey: CryptoKey | Uint8Array
): Promise<VerifiableCredential<T>> {
    if (!vc.proof.jwt) {
        throw new Error('VC does not contain a JWT proof');
    }

    // Pass CryptoKey directly (jose accepts it); for Uint8Array, parse+import as JWK
    const key = publicKey instanceof Uint8Array
        ? await importJWK(JSON.parse(new TextDecoder().decode(publicKey)))
        : publicKey;

    const { payload } = await jwtVerify(vc.proof.jwt, key);
    // The payload contains `{ vc: <original VC without proof> }`
    return (payload as Record<string, unknown>).vc as VerifiableCredential<T>;
}

/**
 * Helper to export a CryptoKey (public or private) to a JWK compatible with `jose`.
 * For non‑extractable private keys this will only export the public part.
 */
export async function exportKeyToJWK(key: CryptoKey): Promise<JsonWebKey> {
    // In Node we can use `crypto.subtle.exportKey`. In the browser the same works
    // for extractable keys. For the PoC we generate keys as non‑extractable, but the
    // public part is always exportable.
    const jwk = await globalThis.crypto.subtle.exportKey('jwk', key) as JsonWebKey;
    return jwk;
}

/**
 * Sign raw string data using an ECDSA private key.
 * Returns a hex-encoded signature.
 */
export async function signData(data: string, privateKey: CryptoKey): Promise<string> {
    const enc = new TextEncoder();
    const signature = await globalThis.crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        privateKey,
        new Uint8Array(enc.encode(data))
    );
    return toHex(new Uint8Array(signature));
}

/**
 * Verify a hex-encoded signature for raw string data using an ECDSA public key.
 */
export async function verifyData(data: string, signatureHex: string, publicKey: CryptoKey): Promise<boolean> {
    const enc = new TextEncoder();
    const signature = fromHex(signatureHex);
    return await globalThis.crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        publicKey,
        signature,
        new Uint8Array(enc.encode(data))
    );
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
