
import {
    decrypt,
    canonicalStringify
} from '@mitch/shared-crypto';
import {
    VerifierRequest
} from '@mitch/shared-types';
import {
    TransportPackage,
    VerificationResult,
    TransportParseError,
    KeyUnwrapError,
    DecryptError,
    AADValidationError,
    ProofSignatureError,
    ReplayDetectedError,
    TokenExpiredError
} from './types';

export interface VerifierConfig {
    privateKey: CryptoKey; // The verifier's RSA-OAEP private key
    verifierDid: string;
    /**
     * Optional callback to check for replays.
     * Should return true if the nonce/decisionId tuple has been seen before.
     */
    replayCheck?: (nonce: string, decisionId: string) => Promise<boolean>;
}

/**
 * miTch Verifier SDK
 * Enables "Privacy-by-Default" verification with strict security boundaries.
 */
export class VerifierSDK {
    constructor(private config: VerifierConfig) { }

    /**
     * Create a secure presentation request for the wallet.
     */
    async createRequest(requestedClaims: string[], purpose: string): Promise<VerifierRequest> {
        return {
            verifierId: this.config.verifierDid,
            requestedClaims,
            purpose,
            origin: globalThis.location?.origin || 'unknown'
        };
    }

    /**
     * Verify and Decrypt the presentation from the wallet.
     * 
     * ENFORCES:
     * 1. Key Unwrapping via Verifier's Private Key
     * 2. AAD Integrity Binding (decision_id, nonce, verifier_did)
     * 3. Replay Protection (via callback)
     * 4. Proof Signature Validation
     */
    async verifyPresentation<T = any>(input: string | TransportPackage): Promise<VerificationResult<T>> {
        let pkg: TransportPackage;

        // 1. Parsing & Validation
        try {
            if (typeof input === 'string') {
                pkg = JSON.parse(input);
            } else {
                pkg = input;
            }
        } catch (e) {
            throw new TransportParseError('JSON parse failed');
        }

        if (!pkg.aad_context || !pkg.recipient?.encrypted_key || !pkg.ciphertext) {
            throw new TransportParseError('Missing required fields (aad_context, recipient, ciphertext)');
        }

        const { ciphertext, aad_context, recipient } = pkg;

        // 2. Unwrap the Ephemeral Session Key
        let ephemeralKey: CryptoKey;
        try {
            const wrappedKeyBytes = this.fromBase64(recipient.encrypted_key);
            // Use sub-slice for WebCrypto compatibility if needed
            const wrappedKeyBuffer = wrappedKeyBytes.buffer.slice(
                wrappedKeyBytes.byteOffset,
                wrappedKeyBytes.byteOffset + wrappedKeyBytes.byteLength
            );

            ephemeralKey = await (globalThis as any).crypto.subtle.unwrapKey(
                'raw',
                wrappedKeyBuffer,
                this.config.privateKey,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
        } catch (e: any) {
            throw new KeyUnwrapError(e.message || 'Check Private Key and Recipient Key Format');
        }

        // 3. AAD Binding Check (Address Verification)
        if (aad_context.verifier_did !== this.config.verifierDid) {
            throw new AADValidationError(`Package addressed to ${aad_context.verifier_did}, expected ${this.config.verifierDid}`);
        }

        // 4. Replay Check
        if (this.config.replayCheck) {
            const isReplay = await this.config.replayCheck(aad_context.nonce, aad_context.decision_id);
            if (isReplay) {
                throw new ReplayDetectedError(aad_context.nonce);
            }
        }

        // 5. Reconstruct AAD for AEAD
        // MUST match Wallet's construction exactly
        const aadBytes = new TextEncoder().encode(
            canonicalStringify({
                decision_id: aad_context.decision_id,
                nonce: aad_context.nonce,
                verifier_did: this.config.verifierDid
            })
        );

        // 6. Decrypt Content (Authenticated Encryption)
        let artifact: any;
        try {
            const plaintext = await decrypt(ciphertext, ephemeralKey, aadBytes);
            artifact = JSON.parse(plaintext);
        } catch (e: any) {
            if (e.message.includes('JSON')) {
                throw new DecryptError('Decrypted payload is not valid JSON');
            }
            throw new DecryptError(e.message || 'Tag mismatch or AAD failure');
        }

        // 7. Verify Artifact Structure
        if (!artifact.proof || !artifact.vp) {
            throw new DecryptError('Missing verified proof boundary in payload');
        }

        // 8. Verify Proof Signature (ECDSA)
        try {
            const signatureBytes = new Uint8Array(
                artifact.proof.signature.match(/.{1,2}/g).map((byte: string) => parseInt(byte, 16))
            );

            const proofPublicKey = await (globalThis as any).crypto.subtle.importKey(
                'jwk',
                artifact.proof.public_key,
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['verify']
            );

            // Canonicalize the VP part of the artifact
            const payloadString = canonicalStringify(artifact.vp);

            const isAuthentic = await (globalThis as any).crypto.subtle.verify(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                proofPublicKey,
                signatureBytes,
                new TextEncoder().encode(payloadString)
            );

            if (!isAuthentic) {
                throw new ProofSignatureError('ECDSA verification returned false');
            }
        } catch (e: any) {
            throw new ProofSignatureError(e.message || 'Crypto operation failed');
        }

        // 9. Cross-Binding Check (Outer AAD vs Inner VP)
        if (artifact.vp.metadata.decision_id !== aad_context.decision_id) {
            throw new AADValidationError('Inner/Outer Decision ID mismatch');
        }
        if (artifact.vp.metadata.nonce !== aad_context.nonce) {
            throw new AADValidationError('Inner/Outer Nonce mismatch');
        }

        // 10. Timestamp / Expiry Check
        if (!artifact.vp.metadata?.timestamp) {
            throw new DecryptError('Missing mandatory timestamp in VP metadata');
        }

        const MAX_AGE = 5 * 60 * 1000; // 5 minutes
        const now = Date.now();
        const issued = artifact.vp.metadata.timestamp;

        if (now - issued > MAX_AGE) {
            throw new TokenExpiredError(now - issued);
        }
        // Clock skew tolerance 30s
        if (issued > now + 30000) {
            throw new TokenExpiredError(-(issued - now)); // Future timestamp
        }

        // Strict Expiry Check (if provided by wallet)
        if (artifact.vp.validUntil && now > artifact.vp.validUntil) {
            throw new TokenExpiredError(now - artifact.vp.validUntil);
        }

        return {
            vp: artifact.vp,
            aad: aad_context,
            proof: {
                verified: true,
                public_key_alg: 'ECDSA-P256'
            },
            timestamp: issued
        };
    }

    private fromBase64(b64: string): Uint8Array {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}
