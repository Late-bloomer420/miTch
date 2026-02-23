/**
 * Verifier-Direct Protocol (Phase-0 Security)
 * 
 * Implements the "Blind Convener" architecture where the wallet communicates
 * directly with the Verifier, bypassing any miTch server relay.
 * 
 * Features:
 * - Direct deep link generation (mitch://present?...)
 * - Direct HTTP POST of VP to Verifier (Structural Non-Existence of Relay)
 */

export const DIRECT_VERIFIER_DID = 'did:mitch:verifier-liquor-store';

export interface DirectSession {
    sessionId: string;
    deepLink: string;
    verifierEndpoint: string;
}

export class VerifierDirectProtocol {
    private verifierBaseUrl: string;

    constructor(verifierBaseUrl = 'http://localhost:3004') {
        this.verifierBaseUrl = verifierBaseUrl;
    }

    async createDirectSession(): Promise<DirectSession> {
        const sessionId = crypto.randomUUID();
        const nonce = crypto.randomUUID();

        // Construct the deep link payload directly
        // Note: In a real scenario, this would be signed by the verifier's key.
        // For Phase-0 PoC, we use a raw query parameter format.
        const params = new URLSearchParams({
            verifier: DIRECT_VERIFIER_DID,
            nonce: nonce,
            callback: `${this.verifierBaseUrl}/present/${sessionId}`,
            // Requested claims (hardcoded for liquor store scenario)
            claims: JSON.stringify(['age', 'birthDate'])
        });

        return {
            sessionId,
            deepLink: `mitch://present?${params.toString()}`,
            verifierEndpoint: `${this.verifierBaseUrl}/present/${sessionId}`
        };
    }

    async submitDirectPresentation(vp: any, callbackUrl: string): Promise<boolean> {
        // This runs on the Wallet side (or harness)
        console.log(`[VerifierDirect] Posting VP to ${callbackUrl}...`);

        try {
            const response = await fetch(callbackUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(vp)
            });

            if (!response.ok) {
                console.error(`[VerifierDirect] Verifier rejected presentation: ${response.statusText}`);
                return false;
            }

            const result = await response.json();
            console.log('[VerifierDirect] Success:', result);
            return true;
        } catch (e) {
            console.error('[VerifierDirect] Network Error:', e);
            return false;
        }
    }
}
