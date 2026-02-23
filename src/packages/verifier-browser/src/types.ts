/**
 * @module @mitch/verifier-browser/types
 * 
 * Type definitions for Browser-Only Verifier SDK
 * Designed for zero-backend integration (e.g., static HTML pages)
 */

/**
 * Configuration for browser verifier session
 */
export interface BrowserVerifierConfig {
    /** Human-readable name of the verifier (e.g., "Joe's Liquor Store") */
    verifierName: string;
    
    /** Purpose of verification (shown to user) */
    purpose: string;
    
    /** Claims required from wallet (e.g., ["age", "birthdate"]) */
    requestedClaims: string[];
    
    /** Claims that should be proven via ZKP (e.g., ["age >= 18"]) */
    requestedProvenClaims?: string[];
    
    /** Session timeout in milliseconds (default: 5 minutes) */
    sessionTimeoutMs?: number;
    
    /** Optional callback URL for result delivery (if not polling) */
    callbackUrl?: string;
}

/**
 * Ephemeral session created for a single verification
 * Keys are generated in-memory and never persisted
 */
export interface VerificationSession {
    /** Unique session ID (UUID) */
    sessionId: string;
    
    /** Ephemeral public key (JWK format) for wallet to encrypt response */
    publicKey: JsonWebKey;
    
    /** Challenge URL (for QR code) */
    challengeUrl: string;
    
    /** Nonce for replay protection */
    nonce: string;
    
    /** Session expiration timestamp */
    expiresAt: number;
    
    /** Internal: Ephemeral private key (never exposed to API consumer) */
    _privateKey?: CryptoKey;
}

/**
 * Response from wallet (encrypted and signed)
 */
export interface WalletResponse {
    /** Session ID this response is for */
    sessionId: string;
    
    /** Encrypted payload (JWE format) */
    encryptedPayload: string;
    
    /** Wallet signature over (sessionId + encryptedPayload) */
    signature: string;
    
    /** Wallet's DID or public key reference */
    walletDid: string;
}

/**
 * Decrypted and verified response content
 */
export interface VerifiedResponse {
    /** Whether verification succeeded */
    success: boolean;
    
    /** Disclosed claims (if any) */
    disclosedClaims?: Record<string, unknown>;
    
    /** ZKP proof results (e.g., { "age >= 18": true }) */
    provenClaims?: Record<string, boolean>;
    
    /** Timestamp of wallet decision */
    timestamp: number;
    
    /** Wallet DID */
    walletDid: string;
    
    /** Error message if verification failed */
    error?: string;
}

/**
 * Session storage interface (default: in-memory Map)
 * Can be overridden for localStorage persistence
 */
export interface SessionStorage {
    set(sessionId: string, session: VerificationSession): Promise<void>;
    get(sessionId: string): Promise<VerificationSession | undefined>;
    delete(sessionId: string): Promise<void>;
}
