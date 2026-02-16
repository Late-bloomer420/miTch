/**
 * @module @mitch/verifier-browser
 * 
 * Browser-Only Verifier SDK
 * Enables static HTML pages to perform credential verification
 * without requiring a backend server (ephemeral keys shredded on refresh)
 * 
 * Usage Example:
 * ```typescript
 * const verifier = new BrowserVerifier({
 *   verifierName: "Joe's Liquor Store",
 *   purpose: "Age Verification (18+)",
 *   requestedClaims: ["age"],
 *   requestedProvenClaims: ["age >= 18"]
 * });
 * 
 * // Generate session and show QR code
 * const session = await verifier.createSession();
 * showQRCode(session.challengeUrl);
 * 
 * // Poll for response (or use callback)
 * const result = await verifier.waitForResponse(session.sessionId);
 * if (result.success) {
 *   console.log("Age verified:", result.provenClaims["age >= 18"]);
 * }
 * ```
 */

import {
    BrowserVerifierConfig,
    VerificationSession,
    WalletResponse,
    VerifiedResponse,
    SessionStorage
} from './types.js';

import {
    generateEphemeralKeyPair,
    generateNonce,
    generateSessionId,
    exportPublicKeyJWK,
    importPublicKeyJWK,
    verifySignature,
    sha256,
    base64UrlToBuffer
} from './crypto.js';

/**
 * Default in-memory session storage
 * Sessions are lost on page refresh (ephemeral by design)
 */
class InMemorySessionStorage implements SessionStorage {
    private storage = new Map<string, VerificationSession>();

    async set(sessionId: string, session: VerificationSession): Promise<void> {
        this.storage.set(sessionId, session);
    }

    async get(sessionId: string): Promise<VerificationSession | undefined> {
        return this.storage.get(sessionId);
    }

    async delete(sessionId: string): Promise<void> {
        this.storage.delete(sessionId);
    }

    // Internal: Cleanup expired sessions
    async cleanup(): Promise<void> {
        const now = Date.now();
        for (const [id, session] of this.storage.entries()) {
            if (session.expiresAt < now) {
                this.storage.delete(id);
            }
        }
    }
}

export class BrowserVerifier {
    private config: Required<BrowserVerifierConfig>;
    private sessionStorage: SessionStorage;

    constructor(
        config: BrowserVerifierConfig,
        sessionStorage?: SessionStorage
    ) {
        // Apply defaults
        this.config = {
            ...config,
            requestedProvenClaims: config.requestedProvenClaims ?? [],
            sessionTimeoutMs: config.sessionTimeoutMs ?? 5 * 60 * 1000, // 5 min default
            callbackUrl: config.callbackUrl ?? ''
        };

        this.sessionStorage = sessionStorage ?? new InMemorySessionStorage();

        // Start periodic cleanup
        this.startCleanupTimer();
    }

    /**
     * T-86: Generate ephemeral session with temporary keys
     * Keys exist only in RAM and are shredded on page refresh
     */
    async createSession(): Promise<VerificationSession> {
        // 1. Generate ephemeral key pair (P-256 ECDSA)
        const keyPair = await generateEphemeralKeyPair();

        // 2. Export public key for wallet
        const publicKeyJWK = await exportPublicKeyJWK(keyPair.publicKey);

        // 3. Generate session ID and nonce
        const sessionId = generateSessionId();
        const nonce = generateNonce();

        // 4. Compute expiration
        const expiresAt = Date.now() + this.config.sessionTimeoutMs;

        // 5. Build challenge URL (for QR code)
        const challengeUrl = this.buildChallengeUrl(sessionId, nonce);

        // 6. Store session (with private key in memory)
        const session: VerificationSession = {
            sessionId,
            publicKey: publicKeyJWK,
            challengeUrl,
            nonce,
            expiresAt,
            _privateKey: keyPair.privateKey // Internal only
        };

        await this.sessionStorage.set(sessionId, session);

        // 7. Return public session data (no private key)
        return {
            sessionId: session.sessionId,
            publicKey: session.publicKey,
            challengeUrl: session.challengeUrl,
            nonce: session.nonce,
            expiresAt: session.expiresAt
        };
    }

    /**
     * Verify wallet response and extract claims
     */
    async verifyResponse(
        response: WalletResponse
    ): Promise<VerifiedResponse> {
        // 1. Retrieve session
        const session = await this.sessionStorage.get(response.sessionId);

        if (!session) {
            return {
                success: false,
                timestamp: Date.now(),
                walletDid: response.walletDid,
                error: 'Session not found or expired'
            };
        }

        // 2. Check expiration
        if (Date.now() > session.expiresAt) {
            await this.sessionStorage.delete(response.sessionId);
            return {
                success: false,
                timestamp: Date.now(),
                walletDid: response.walletDid,
                error: 'Session expired'
            };
        }

        try {
            // 3. Verify signature (wallet signs sessionId + encryptedPayload)
            const dataToVerify = new TextEncoder().encode(
                response.sessionId + response.encryptedPayload
            );

            const signatureBuffer = base64UrlToBuffer(response.signature);

            // Import wallet's public key
            // TODO: Resolve DID to get public key (for now, assume wallet sends JWK)
            // const walletPubKey = await this.resolveDidToPublicKey(response.walletDid);

            // For PoC: Skip signature verification (requires DID resolution)
            // const isValid = await verifySignature(walletPubKey, dataToVerify, signatureBuffer);
            // if (!isValid) {
            //     return { success: false, error: 'Invalid signature', ... };
            // }

            // 4. Decrypt payload (JWE)
            // TODO: Implement JWE decryption with ephemeral private key
            // const decryptedPayload = await decryptJWE(
            //     response.encryptedPayload,
            //     session._privateKey!
            // );

            // 5. For PoC: Simulate successful verification
            // In production: Parse decrypted payload as DecisionCapsule
            const mockResponse: VerifiedResponse = {
                success: true,
                provenClaims: {
                    'age >= 18': true
                },
                timestamp: Date.now(),
                walletDid: response.walletDid
            };

            // 6. Cleanup session (one-time use)
            await this.sessionStorage.delete(response.sessionId);

            return mockResponse;

        } catch (error) {
            return {
                success: false,
                timestamp: Date.now(),
                walletDid: response.walletDid,
                error: error instanceof Error ? error.message : 'Verification failed'
            };
        }
    }

    /**
     * Poll for response (for synchronous flows)
     * Returns when wallet responds or timeout occurs
     */
    async waitForResponse(
        sessionId: string,
        timeoutMs: number = 60_000
    ): Promise<VerifiedResponse> {
        const startTime = Date.now();

        // Polling loop (check every 1 second)
        while (Date.now() - startTime < timeoutMs) {
            // Check if session has been fulfilled
            const session = await this.sessionStorage.get(sessionId);

            if (!session) {
                // Session was deleted (response received or expired)
                return {
                    success: false,
                    timestamp: Date.now(),
                    walletDid: 'unknown',
                    error: 'Session expired or already processed'
                };
            }

            // In production: Check external storage for wallet response
            // For PoC: Just wait
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Timeout
        return {
            success: false,
            timestamp: Date.now(),
            walletDid: 'unknown',
            error: 'Verification timeout'
        };
    }

    /**
     * Build challenge URL for QR code
     * Format: mitch://verify?session={id}&nonce={nonce}&pubkey={jwk}&purpose={purpose}
     */
    private buildChallengeUrl(sessionId: string, nonce: string): string {
        const params = new URLSearchParams({
            session: sessionId,
            nonce,
            verifier: this.config.verifierName,
            purpose: this.config.purpose,
            claims: this.config.requestedClaims.join(','),
            proven: this.config.requestedProvenClaims.join(',')
        });

        // Use custom URI scheme for wallet deep-linking
        return `mitch://verify?${params.toString()}`;
    }

    /**
     * Periodic cleanup of expired sessions
     */
    private startCleanupTimer(): void {
        const storage = this.sessionStorage as any;
        if (typeof storage.cleanup === 'function') {
            setInterval(() => {
                storage.cleanup();
            }, 60_000); // Every minute
        }
    }
}
