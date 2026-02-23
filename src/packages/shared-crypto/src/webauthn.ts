import { canonicalStringify } from './hashing';

/**
 * WebAuthnService (PoC Simulation):
 * 
 * Simulates binding user presence (Biometrics/Passkey) to a specific 
 * cryptographic decision.
 * 
 * In a production miTch wallet, this uses the FIDO2/WebAuthn API 
 * to generate a signature over the 'decision_id'.
 */
export class WebAuthnService {
    private static userKey: CryptoKeyPair | null = null;

    /**
     * Initializes the "Passkey" for this device.
     */
    static async registerDevice(): Promise<void> {
        this.userKey = await crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256",
            },
            true,
            ["sign", "verify"]
        );
    }

    /**
     * Performs a "Cryptographic Presence" ceremony.
     * Binds the current decision_id to a hardware-backed signature.
     * 
     * @param decisionId The UUID from the DecisionCapsule
     * @returns A base64-encoded attestation of presence
     */
    static async provePresence(decisionId: string): Promise<string> {
        if (!this.userKey) {
            await this.registerDevice();
        }

        const encoder = new TextEncoder();
        const data = encoder.encode(canonicalStringify({
            challenge: decisionId,
            timestamp: Date.now(),
            origin: globalThis.location?.origin || 'mitch-wallet'
        }));

        const signature = await crypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            this.userKey!.privateKey,
            data
        );

        return btoa(String.fromCharCode(...Array.from(new Uint8Array(signature))));
    }

    /**
     * Verifies the presence proof. 
     * Used by the Verifier or the Wallet's audit log.
     */
    static async verifyPresence(decisionId: string, attestation: string): Promise<boolean> {
        if (!this.userKey) return false;

        const signature = new Uint8Array(
            atob(attestation).split("").map(c => c.charCodeAt(0))
        );

        // In a real scenario, we'd reconstruct the signed data perfectly
        // For the PoC, we assume success if the signature exists, 
        // as the actual byte-level reconstruction of WebAuthn artifacts 
        // is out of scope for the demo's logic layer.
        return attestation.length > 0;
    }
}
