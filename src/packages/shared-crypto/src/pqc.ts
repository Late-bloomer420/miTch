/**
 * @module @mitch/shared-crypto/pqc
 *
 * Post-Quantum Cryptography — Spec 93 (Live Implementation)
 *
 * Backed by @noble/post-quantum (v0.5.x, pure JS, zero native deps).
 * Exports thin wrappers with a consistent `(key, message)` argument order
 * that matches the rest of the codebase, hiding noble's internal conventions.
 *
 * Algorithms provided:
 *   Signing:     ML-DSA-44 / ML-DSA-65 / ML-DSA-87  (FIPS 204, formerly CRYSTALS-Dilithium)
 *                SLH-DSA-SHA2-128s                    (FIPS 205, formerly SPHINCS+)
 *   KEM:         ML-KEM-512 / ML-KEM-768             (FIPS 203, formerly CRYSTALS-Kyber)
 *   Hybrid:      ES256 + ML-DSA-44                   (ECDSA P-256 || ML-DSA-44 composite)
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

// ─── Shared types ─────────────────────────────────────────────────────────────

export interface PQCKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

/** Wrapper presenting a consistent `sign(secretKey, msg)` / `verify(publicKey, msg, sig)` API. */
export interface PQCSigner {
    /** Key lengths in bytes */
    readonly lengths: { publicKey: number; secretKey: number; signature: number };
    keygen(seed?: Uint8Array): PQCKeyPair;
    sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array;
    verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

/** Wrapper for ML-KEM key encapsulation. */
export interface PQCKEM {
    readonly lengths: { publicKey: number; secretKey: number; cipherText: number; sharedSecret: number };
    keygen(seed?: Uint8Array): PQCKeyPair;
    /**
     * Encapsulate: generate shared secret and ciphertext using receiver's public key.
     * Returns `{ cipherText, sharedSecret }` — both as Uint8Array.
     */
    encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
    /**
     * Decapsulate: recover shared secret from ciphertext using receiver's secret key.
     */
    decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

// ─── ML-DSA wrappers ──────────────────────────────────────────────────────────

function makeDSA(suite: typeof ml_dsa44): PQCSigner {
    return {
        lengths: {
            publicKey: suite.lengths.publicKey!,
            secretKey: suite.lengths.secretKey!,
            signature: suite.lengths.signature!,
        },
        keygen: (seed?) => suite.keygen(seed),
        sign:   (secretKey, message) => suite.sign(message, secretKey),
        verify: (publicKey, message, signature) => suite.verify(signature, message, publicKey),
    };
}

/** ML-DSA-44 — NIST Level 1 (128-bit PQC). Signature: 2420 bytes. */
export const mlDSA44: PQCSigner = makeDSA(ml_dsa44);

/** ML-DSA-65 — NIST Level 3 (192-bit PQC). Signature: 3309 bytes. */
export const mlDSA65: PQCSigner = makeDSA(ml_dsa65);

/** ML-DSA-87 — NIST Level 5 (256-bit PQC). Signature: 4627 bytes. */
export const mlDSA87: PQCSigner = makeDSA(ml_dsa87);

// ─── SLH-DSA wrapper ─────────────────────────────────────────────────────────

/** SLH-DSA-SHA2-128s — NIST Level 1 stateless hash-based signing (FIPS 205). */
export const slhDSASHA2128s: PQCSigner = {
    lengths: {
        publicKey: slh_dsa_sha2_128s.lengths.publicKey!,
        secretKey: slh_dsa_sha2_128s.lengths.secretKey!,
        signature: slh_dsa_sha2_128s.lengths.signature!,
    },
    keygen: (seed?) => slh_dsa_sha2_128s.keygen(seed),
    sign:   (secretKey, message) => slh_dsa_sha2_128s.sign(message, secretKey),
    verify: (publicKey, message, signature) => slh_dsa_sha2_128s.verify(signature, message, publicKey),
};

// ─── ML-KEM wrappers ─────────────────────────────────────────────────────────

function makeKEM(suite: typeof ml_kem512): PQCKEM {
    return {
        lengths: {
            publicKey:    suite.lengths.publicKey!,
            secretKey:    suite.lengths.secretKey!,
            cipherText:   suite.lengths.cipherText!,
            sharedSecret: 32, // ML-KEM always produces a 32-byte shared secret
        },
        keygen: (seed?) => suite.keygen(seed),
        encapsulate: (publicKey) => suite.encapsulate(publicKey),
        decapsulate: (cipherText, secretKey) => suite.decapsulate(cipherText, secretKey),
    };
}

/** ML-KEM-512 — NIST Level 1. Ciphertext: 768 bytes. Shared secret: 32 bytes. */
export const mlKEM512: PQCKEM = makeKEM(ml_kem512);

/** ML-KEM-768 — NIST Level 3. Ciphertext: 1088 bytes. Shared secret: 32 bytes. */
export const mlKEM768: PQCKEM = makeKEM(ml_kem768);

// ─── Hybrid: ES256 + ML-DSA-44 ───────────────────────────────────────────────
//
// Composite: sign with both ECDSA-P256 (classical) and ML-DSA-44 (PQC).
// Verification requires BOTH to pass — fail-closed.
//
// Composite signature wire format (deterministic, no JSON overhead):
//   [0..3]   big-endian uint32 = ECDSA signature length (64 for P-256 raw r||s)
//   [4..67]  ECDSA signature bytes
//   [68..71] big-endian uint32 = ML-DSA-44 signature length
//   [72..]   ML-DSA-44 signature bytes

export interface HybridDSAPublicKey {
    ecdsa: CryptoKey;   // P-256 ECDSA public key
    pqc:   Uint8Array;  // ML-DSA-44 public key (1312 bytes)
}

export interface HybridDSASecretKey {
    ecdsa: CryptoKey;   // P-256 ECDSA private key
    pqc:   Uint8Array;  // ML-DSA-44 secret key (2560 bytes)
}

export interface HybridDSAKeyPair {
    publicKey: HybridDSAPublicKey;
    secretKey: HybridDSASecretKey;
}

export const hybridMLDSA44 = {
    /**
     * Generate a hybrid key pair.
     * Classical: ECDSA P-256 (WebCrypto ephemeral).
     * PQC: ML-DSA-44.
     */
    async keygen(): Promise<HybridDSAKeyPair> {
        const [ecPair, pqcPair] = await Promise.all([
            crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign', 'verify'],
            ),
            Promise.resolve(ml_dsa44.keygen()),
        ]);
        return {
            publicKey: { ecdsa: ecPair.publicKey, pqc: pqcPair.publicKey },
            secretKey: { ecdsa: ecPair.privateKey, pqc: pqcPair.secretKey },
        };
    },

    /**
     * Sign a message with both ECDSA-P256 and ML-DSA-44.
     * Returns a composite Uint8Array (length-prefixed binary format).
     */
    async sign(secretKey: HybridDSASecretKey, message: Uint8Array): Promise<Uint8Array> {
        const [ecSigBuf, pqcSig] = await Promise.all([
            crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, secretKey.ecdsa, message.buffer as ArrayBuffer),
            Promise.resolve(ml_dsa44.sign(message, secretKey.pqc)),
        ]);

        const ecSig = new Uint8Array(ecSigBuf);
        return encodeComposite(ecSig, pqcSig);
    },

    /**
     * Verify a composite hybrid signature.
     * Requires BOTH classical and PQC verification to pass.
     */
    async verify(
        publicKey: HybridDSAPublicKey,
        message: Uint8Array,
        compositeSignature: Uint8Array,
    ): Promise<boolean> {
        const { classical: ecSig, pqc: pqcSig } = decodeComposite(compositeSignature);

        const [ecOk, pqcOk] = await Promise.all([
            crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' },
                publicKey.ecdsa,
                ecSig.buffer as ArrayBuffer,
                message.buffer as ArrayBuffer,
            ),
            Promise.resolve(ml_dsa44.verify(pqcSig, message, publicKey.pqc)),
        ]);

        // Fail-closed: both must pass
        return ecOk && pqcOk;
    },
} as const;

// ─── Composite signature codec ────────────────────────────────────────────────

/** Encode two byte arrays into a length-prefixed composite buffer. */
function encodeComposite(classical: Uint8Array, pqc: Uint8Array): Uint8Array {
    const out = new Uint8Array(4 + classical.length + 4 + pqc.length);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, classical.length, false);
    out.set(classical, 4);
    dv.setUint32(4 + classical.length, pqc.length, false);
    out.set(pqc, 4 + classical.length + 4);
    return out;
}

function decodeComposite(buf: Uint8Array): { classical: Uint8Array; pqc: Uint8Array } {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const classicalLen = dv.getUint32(0, false);
    const classical = buf.slice(4, 4 + classicalLen);
    const pqcLen = dv.getUint32(4 + classicalLen, false);
    const pqc = buf.slice(4 + classicalLen + 4, 4 + classicalLen + 4 + pqcLen);
    if (pqc.length !== pqcLen) {
        throw new Error('HYBRID_DECODE_FAILED: truncated composite signature');
    }
    return { classical, pqc };
}

// ─── Registry integration helpers ────────────────────────────────────────────

/**
 * Resolve a registered algorithm ID to its PQC implementation.
 * Returns `null` for classical algorithms (not handled here).
 */
export function resolvePQCSigner(algorithmId: string): PQCSigner | null {
    switch (algorithmId) {
        case 'ML-DSA-44':        return mlDSA44;
        case 'ML-DSA-65':        return mlDSA65;
        case 'ML-DSA-87':        return mlDSA87;
        case 'SLH-DSA-SHA2-128s': return slhDSASHA2128s;
        default: return null;
    }
}

export function resolvePQCKEM(algorithmId: string): PQCKEM | null {
    switch (algorithmId) {
        case 'ML-KEM-512': return mlKEM512;
        case 'ML-KEM-768': return mlKEM768;
        default: return null;
    }
}
