
export interface TransportPackage {
    ciphertext: string; // Base64
    aad_context: {
        decision_id: string;
        nonce: string;
        verifier_did: string;
    };
    recipient: {
        header: { kid: string };
        encrypted_key: string; // Base64 wrapped Ephemeral Key
    };
}

/** Runtime type guard for JSON.parse output — narrows unknown to TransportPackage */
export function isTransportPackage(v: unknown): v is TransportPackage {
    if (typeof v !== 'object' || v === null) return false;
    const o = v as Record<string, unknown>;
    if (typeof o['ciphertext'] !== 'string') return false;
    const aad = o['aad_context'];
    if (typeof aad !== 'object' || aad === null) return false;
    const a = aad as Record<string, unknown>;
    if (typeof a['decision_id'] !== 'string') return false;
    if (typeof a['nonce'] !== 'string') return false;
    if (typeof a['verifier_did'] !== 'string') return false;
    const rec = o['recipient'];
    if (typeof rec !== 'object' || rec === null) return false;
    const r = rec as Record<string, unknown>;
    if (typeof r['encrypted_key'] !== 'string') return false;
    return true;
}

export interface VerificationResult<T = unknown> {
    vp: T;
    aad: TransportPackage['aad_context'];
    proof: {
        verified: boolean;
        public_key_alg: string;
    };
    timestamp: number;
}

// --- Error Taxonomy ---

export class VerifierError extends Error {
    constructor(message: string, public code: string) {
        super(message);
        this.name = this.constructor.name;
    }
}

export class TransportParseError extends VerifierError {
    constructor(details: string) { super(`Transport Package Invalid: ${details}`, 'TRANSPORT_PARSE_ERROR'); }
}

export class KeyUnwrapError extends VerifierError {
    constructor(details: string) { super(`Key Unwrap Failed: ${details}`, 'KEY_UNWRAP_ERROR'); }
}

export class DecryptError extends VerifierError {
    constructor(details: string) { super(`Decryption Failed (AEAD): ${details}`, 'DECRYPT_ERROR'); }
}

export class AADValidationError extends VerifierError {
    constructor(details: string) { super(`AAD Binding Violation: ${details}`, 'AAD_VALIDATION_ERROR'); }
}

export class ProofSignatureError extends VerifierError {
    constructor(details: string) { super(`Proof Signature Invalid: ${details}`, 'PROOF_SIGNATURE_ERROR'); }
}

export class ReplayDetectedError extends VerifierError {
    constructor(nonce: string) { super(`Replay Detected: Nonce ${nonce} already seen`, 'REPLAY_DETECTED'); }
}

export class TokenExpiredError extends VerifierError {
    constructor(ageMs: number) { super(`Token Expired: Age ${ageMs}ms > TTL`, 'TOKEN_EXPIRED'); }
}
