
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

export interface VerificationResult<T = any> {
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
