/**
 * BSI/SOG-IS Brainpool Curve Support — C-01
 * https://www.rfc-editor.org/rfc/rfc5639 (Brainpool Curves)
 *
 * WebCrypto does NOT support Brainpool curves natively (only NIST/secp256r1).
 * This module uses @noble/curves + @noble/hashes as a pure-JS fallback.
 *
 * Supported:
 * - brainpoolP256r1 (256-bit, RFC 5639 §3.4)
 * - brainpoolP384r1 (384-bit, RFC 5639 §3.6)
 *
 * Production note: Brainpool curve implementations for qualified signatures
 * MUST use BSI-certified implementations (e.g. via PKCS#11/HSM).
 */

import { weierstrass, ecdsa } from '@noble/curves/abstract/weierstrass.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';

// ─── brainpoolP256r1 Parameters (RFC 5639 §3.4) ─────────────────────────────

const BP256_CURVE = {
    // 256-bit prime field
    p: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n,
    a: 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9n,
    b: 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6n,
    // Generator point
    Gx: 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262n,
    Gy: 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997n,
    // Group order
    n: 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
    h: 1n,
};

const bp256Point = weierstrass(BP256_CURVE);
const bp256ECDSA = ecdsa(bp256Point, sha256);

// ─── brainpoolP384r1 Parameters (RFC 5639 §3.6) ─────────────────────────────

const BP384_CURVE = {
    // 384-bit prime field
    p: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n,
    a: 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826n,
    b: 0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11n,
    // Generator point
    Gx: 0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1en,
    Gy: 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315n,
    // Group order
    n: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
    h: 1n,
};

const bp384Point = weierstrass(BP384_CURVE);
const bp384ECDSA = ecdsa(bp384Point, sha384);

// ─── Curve Dispatch ──────────────────────────────────────────────────────────

function getEcdsa(curve: BrainpoolCurve) {
    return curve === 'brainpoolP384r1' ? bp384ECDSA : bp256ECDSA;
}

function getCoordLength(curve: BrainpoolCurve): number {
    return curve === 'brainpoolP384r1' ? 48 : 32;
}

// ─── Public Types ─────────────────────────────────────────────────────────────

export type BrainpoolCurve = 'brainpoolP256r1' | 'brainpoolP384r1';

export interface BrainpoolKeyPair {
    curve: BrainpoolCurve;
    /** Private key scalar (raw bytes) */
    privateKey: Uint8Array;
    /** Compressed public key bytes */
    publicKey: Uint8Array;
}

export interface BrainpoolSignature {
    /** Compact ECDSA signature (r||s) */
    signature: Uint8Array;
    curve: BrainpoolCurve;
}

// ─── Key Generation ───────────────────────────────────────────────────────────

/**
 * Generate a Brainpool key pair.
 */
export function generateBrainpoolKeyPair(curve: BrainpoolCurve): BrainpoolKeyPair {
    const ec = getEcdsa(curve);
    const privKey = ec.utils.randomSecretKey() as Uint8Array;
    const pubKey = ec.getPublicKey(privKey) as Uint8Array;
    return { curve, privateKey: privKey, publicKey: pubKey };
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/**
 * Sign data with a Brainpool private key (ECDSA, prehash=true).
 * Returns compact signature (r||s Uint8Array).
 */
export function signWithBrainpool(data: Uint8Array, keyPair: BrainpoolKeyPair): BrainpoolSignature {
    const ec = getEcdsa(keyPair.curve);
    const signature = ec.sign(data, keyPair.privateKey, { prehash: true }) as Uint8Array;
    return { signature, curve: keyPair.curve };
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify a Brainpool ECDSA signature.
 */
export function verifyWithBrainpool(
    data: Uint8Array,
    sig: BrainpoolSignature,
    publicKey: Uint8Array
): boolean {
    const ec = getEcdsa(sig.curve);
    return ec.verify(sig.signature, data, publicKey, { prehash: true }) as boolean;
}

// ─── ECDH ─────────────────────────────────────────────────────────────────────

/**
 * Brainpool ECDH shared secret computation.
 */
export function brainpoolECDH(
    privateKey: Uint8Array,
    publicKey: Uint8Array,
    curve: BrainpoolCurve
): Uint8Array {
    const ec = getEcdsa(curve);
    return ec.getSharedSecret(privateKey, publicKey) as Uint8Array;
}

// ─── Key Export ───────────────────────────────────────────────────────────────

/**
 * Encode a Brainpool public key as a transport object.
 * Note: JWA/JWK does not natively support brainpool curves.
 */
export function brainpoolPublicKeyToObject(keyPair: BrainpoolKeyPair): Record<string, string> {
    const pub = keyPair.publicKey;
    const coordLen = getCoordLength(keyPair.curve);
    const x = pub.slice(1, 1 + coordLen);
    return {
        kty: 'EC',
        crv: keyPair.curve,
        x: toBase64url(x),
    };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toBase64url(bytes: Uint8Array): string {
    const b64 = btoa(String.fromCharCode(...bytes));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
