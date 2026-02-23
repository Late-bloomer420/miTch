/**
 * Standardized Reason Codes for miTch Workflow
 * 
 * Maps workflow invariants to machine-readable error codes.
 * Used across PolicyEngine, WalletService, and VerifierSDK.
 */

export enum ReasonCode {
    // ========================================
    // Invariant 1: Request Integrity
    // ========================================
    INVALID_REQUEST = 'INVALID_REQUEST',
    MISSING_VERIFIER_ID = 'MISSING_VERIFIER_ID',
    MISSING_CHALLENGE = 'MISSING_CHALLENGE',
    MISSING_PURPOSE = 'MISSING_PURPOSE',
    INVALID_PURPOSE = 'INVALID_PURPOSE',  // Generic or empty purpose
    
    // ========================================
    // Invariant 2: Unknown Verifier Blocking
    // ========================================
    VERIFIER_NOT_ALLOWED = 'VERIFIER_NOT_ALLOWED',
    VERIFIER_UNRESOLVABLE = 'VERIFIER_UNRESOLVABLE',
    VERIFIER_PATTERN_MISMATCH = 'VERIFIER_PATTERN_MISMATCH',
    
    // ========================================
    // Invariant 3: Claim Denial
    // ========================================
    CLAIM_DENIED = 'CLAIM_DENIED',
    CLAIM_NOT_AVAILABLE = 'CLAIM_NOT_AVAILABLE',
    CLAIM_NOT_PERMITTED = 'CLAIM_NOT_PERMITTED',
    
    // ========================================
    // Invariant 4: Presence Requirement
    // ========================================
    PRESENCE_REQUIRED = 'PRESENCE_REQUIRED',
    AUTHENTICATOR_MISSING = 'AUTHENTICATOR_MISSING',
    WEBAUTHN_FAILED = 'WEBAUTHN_FAILED',
    PRESENCE_PROOF_INVALID = 'PRESENCE_PROOF_INVALID',
    
    // ========================================
    // Invariant 5: Issuer Trust
    // ========================================
    ISSUER_NOT_TRUSTED = 'ISSUER_NOT_TRUSTED',
    ISSUER_SIGNATURE_INVALID = 'ISSUER_SIGNATURE_INVALID',
    ISSUER_REVOKED = 'ISSUER_REVOKED',
    
    // ========================================
    // Invariant 6: Replay Protection
    // ========================================
    REPLAY_DETECTED = 'REPLAY_DETECTED',
    NONCE_ALREADY_USED = 'NONCE_ALREADY_USED',
    NONCE_STORE_FULL = 'NONCE_STORE_FULL',
    
    // ========================================
    // Invariant 7: Temporal Validity
    // ========================================
    REQUEST_EXPIRED = 'REQUEST_EXPIRED',
    CREDENTIAL_EXPIRED = 'CREDENTIAL_EXPIRED',
    TOKEN_EXPIRED = 'TOKEN_EXPIRED',
    TIMESTAMP_OUT_OF_BOUNDS = 'TIMESTAMP_OUT_OF_BOUNDS',
    
    // ========================================
    // Consent & User Actions
    // ========================================
    USER_DENIED = 'USER_DENIED',
    CONSENT_TIMEOUT = 'CONSENT_TIMEOUT',
    CONSENT_REQUIRED = 'CONSENT_REQUIRED',
    
    // ========================================
    // Cryptographic Failures
    // ========================================
    SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',
    ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
    DECRYPTION_FAILED = 'DECRYPTION_FAILED',
    KEY_DERIVATION_FAILED = 'KEY_DERIVATION_FAILED',
    
    // ========================================
    // ZKP / Predicate Failures
    // ========================================
    PREDICATE_NOT_SATISFIED = 'PREDICATE_NOT_SATISFIED',
    ZKP_PROOF_INVALID = 'ZKP_PROOF_INVALID',
    ZKP_BINDING_MISMATCH = 'ZKP_BINDING_MISMATCH',
    
    // ========================================
    // Storage & Infrastructure
    // ========================================
    STORAGE_LOCKED = 'STORAGE_LOCKED',
    STORAGE_CORRUPTED = 'STORAGE_CORRUPTED',
    CREDENTIAL_NOT_FOUND = 'CREDENTIAL_NOT_FOUND',
    
    // ========================================
    // Network & Resolution
    // ========================================
    DID_RESOLUTION_FAILED = 'DID_RESOLUTION_FAILED',
    NETWORK_OFFLINE = 'NETWORK_OFFLINE',
    NETWORK_TIMEOUT = 'NETWORK_TIMEOUT',
    
    // ========================================
    // Generic
    // ========================================
    INTERNAL_ERROR = 'INTERNAL_ERROR',
    UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

/**
 * Human-readable error messages for each code.
 */
export const ReasonMessages: Record<ReasonCode, string> = {
    // Request Integrity
    [ReasonCode.INVALID_REQUEST]: 'The request is malformed or missing required fields.',
    [ReasonCode.MISSING_VERIFIER_ID]: 'Verifier identity (DID or origin) is required.',
    [ReasonCode.MISSING_CHALLENGE]: 'Anti-replay challenge/nonce is required.',
    [ReasonCode.MISSING_PURPOSE]: 'Request must declare a specific purpose.',
    [ReasonCode.INVALID_PURPOSE]: 'Purpose cannot be generic (e.g., "general use").',
    
    // Verifier Blocking
    [ReasonCode.VERIFIER_NOT_ALLOWED]: 'This verifier is not in your trusted list.',
    [ReasonCode.VERIFIER_UNRESOLVABLE]: 'Could not resolve verifier DID or identity.',
    [ReasonCode.VERIFIER_PATTERN_MISMATCH]: 'Verifier does not match any policy rule.',
    
    // Claim Denial
    [ReasonCode.CLAIM_DENIED]: 'One or more requested claims are blocked by policy.',
    [ReasonCode.CLAIM_NOT_AVAILABLE]: 'You do not have the requested credential.',
    [ReasonCode.CLAIM_NOT_PERMITTED]: 'Policy does not allow sharing this claim with this verifier.',
    
    // Presence
    [ReasonCode.PRESENCE_REQUIRED]: 'This action requires biometric or physical presence.',
    [ReasonCode.AUTHENTICATOR_MISSING]: 'No registered authenticator (passkey) found.',
    [ReasonCode.WEBAUTHN_FAILED]: 'WebAuthn ceremony failed or was cancelled.',
    [ReasonCode.PRESENCE_PROOF_INVALID]: 'The presence proof signature is invalid.',
    
    // Issuer Trust
    [ReasonCode.ISSUER_NOT_TRUSTED]: 'Credential issuer is not in your trusted list.',
    [ReasonCode.ISSUER_SIGNATURE_INVALID]: 'Credential signature verification failed.',
    [ReasonCode.ISSUER_REVOKED]: 'This issuer has been revoked.',
    
    // Replay Protection
    [ReasonCode.REPLAY_DETECTED]: 'This challenge/nonce was already used (replay attack detected).',
    [ReasonCode.NONCE_ALREADY_USED]: 'Nonce has been seen before.',
    [ReasonCode.NONCE_STORE_FULL]: 'Nonce store at capacity (DoS protection).',
    
    // Temporal Validity
    [ReasonCode.REQUEST_EXPIRED]: 'Request timestamp is outside acceptable window (±5 min).',
    [ReasonCode.CREDENTIAL_EXPIRED]: 'Credential is too old per policy constraints.',
    [ReasonCode.TOKEN_EXPIRED]: 'Presentation token has expired.',
    [ReasonCode.TIMESTAMP_OUT_OF_BOUNDS]: 'Timestamp validation failed.',
    
    // Consent
    [ReasonCode.USER_DENIED]: 'You denied this request.',
    [ReasonCode.CONSENT_TIMEOUT]: 'Consent prompt timed out without user response.',
    [ReasonCode.CONSENT_REQUIRED]: 'This action requires explicit user consent.',
    
    // Crypto
    [ReasonCode.SIGNATURE_VERIFICATION_FAILED]: 'Digital signature verification failed.',
    [ReasonCode.ENCRYPTION_FAILED]: 'Failed to encrypt data.',
    [ReasonCode.DECRYPTION_FAILED]: 'Failed to decrypt data.',
    [ReasonCode.KEY_DERIVATION_FAILED]: 'Key derivation from PIN/password failed.',
    
    // ZKP
    [ReasonCode.PREDICATE_NOT_SATISFIED]: 'The predicate (e.g., age >= 18) is not satisfied.',
    [ReasonCode.ZKP_PROOF_INVALID]: 'Zero-knowledge proof verification failed.',
    [ReasonCode.ZKP_BINDING_MISMATCH]: 'ZKP proof binding does not match request.',
    
    // Storage
    [ReasonCode.STORAGE_LOCKED]: 'Wallet is locked. Please unlock with PIN.',
    [ReasonCode.STORAGE_CORRUPTED]: 'Storage integrity check failed.',
    [ReasonCode.CREDENTIAL_NOT_FOUND]: 'Requested credential not found in wallet.',
    
    // Network
    [ReasonCode.DID_RESOLUTION_FAILED]: 'Failed to resolve DID document.',
    [ReasonCode.NETWORK_OFFLINE]: 'Network is offline.',
    [ReasonCode.NETWORK_TIMEOUT]: 'Network request timed out.',
    
    // Generic
    [ReasonCode.INTERNAL_ERROR]: 'An internal error occurred.',
    [ReasonCode.UNKNOWN_ERROR]: 'An unknown error occurred.',
};

/**
 * Map reason codes to HTTP status codes (for verifier responses)
 */
export const ReasonHttpStatus: Partial<Record<ReasonCode, number>> = {
    [ReasonCode.INVALID_REQUEST]: 400,
    [ReasonCode.MISSING_VERIFIER_ID]: 400,
    [ReasonCode.MISSING_CHALLENGE]: 400,
    [ReasonCode.MISSING_PURPOSE]: 400,
    [ReasonCode.VERIFIER_NOT_ALLOWED]: 403,
    [ReasonCode.CLAIM_DENIED]: 403,
    [ReasonCode.USER_DENIED]: 403,
    [ReasonCode.PRESENCE_REQUIRED]: 401,
    [ReasonCode.ISSUER_NOT_TRUSTED]: 422,
    [ReasonCode.REPLAY_DETECTED]: 409,
    [ReasonCode.REQUEST_EXPIRED]: 410,
    [ReasonCode.CREDENTIAL_EXPIRED]: 410,
    [ReasonCode.TOKEN_EXPIRED]: 410,
    [ReasonCode.SIGNATURE_VERIFICATION_FAILED]: 401,
    [ReasonCode.ZKP_PROOF_INVALID]: 422,
    [ReasonCode.STORAGE_LOCKED]: 423,
    [ReasonCode.DID_RESOLUTION_FAILED]: 502,
    [ReasonCode.NETWORK_OFFLINE]: 503,
    [ReasonCode.INTERNAL_ERROR]: 500,
};

/**
 * Helper to format error for user display
 */
export function formatReasonCode(code: ReasonCode, context?: Record<string, unknown>): {
    code: ReasonCode;
    message: string;
    httpStatus: number;
    context?: Record<string, unknown>;
} {
    return {
        code,
        message: ReasonMessages[code] || ReasonMessages[ReasonCode.UNKNOWN_ERROR],
        httpStatus: ReasonHttpStatus[code] || 400,
        context,
    };
}
