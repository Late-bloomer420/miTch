import express from 'express';
import { VerifierSDK } from '@mitch/verifier-sdk';

const app = express();
const port = 3001;

app.use(express.json());

// Pilot State (In-memory for PoC)
let lastVerificationStatus: 'WAITING' | 'VERIFIED' | 'FAILED' = 'WAITING';
let verifierKeys: CryptoKeyPair | null = null;

/**
 * miTch Pilot Verifier Endpoints
 */

// 1. Get current status (for the frontend polling)
app.get('/status', (req, res) => {
    res.json({
        status: lastVerificationStatus,
        verifierDid: 'did:mitch:verifier-liquor-store'
    });
});

// 2. Receive and Verify Presentation (The "Consumer" of the SDK)
app.post('/present', async (req, res) => {
    console.log('📥 Received presentation package from wallet');

    try {
        if (!verifierKeys) {
            // Lazy-init keys for PoC. In production, these are persistent.
            verifierKeys = await globalThis.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["decrypt", "unwrapKey"]
            );
        }

        const sdk = new VerifierSDK({
            privateKey: verifierKeys!.privateKey,
            verifierDid: 'did:mitch:verifier-liquor-store'
        });

        // The Magic: SDK handles unwrapping, AAD re-binding, and Decryption
        const presentation = await sdk.verifyPresentation<Record<string, unknown>>(JSON.stringify(req.body));

        console.log('🔓 Decrypted Presentation Payload:', presentation);

        // Pilot Logic: Age Verification
        if (presentation.disclosure?.isOver18 === true) {
            lastVerificationStatus = 'VERIFIED';
            console.log('✅ AGE VERIFIED: Result = ALLOW');
            res.json({ ok: true, message: 'Welcome to the liquor store!' });
        } else {
            lastVerificationStatus = 'FAILED';
            console.log('❌ VERIFICATION FAILED: minor detected');
            res.status(403).json({ ok: false, error: 'AGE_NOT_VERIFIED' });
        }
    } catch (e: unknown) {
        console.error('🔥 Critical Decryption Error:', e instanceof Error ? e.message : String(e));
        lastVerificationStatus = 'FAILED';
        res.status(400).json({ ok: false, error: 'DECRYPTION_FAILED', details: e instanceof Error ? e.message : String(e) });
    }
});

// 3. Reset (for demo repeat)
app.post('/reset', (req, res) => {
    lastVerificationStatus = 'WAITING';
    res.json({ ok: true });
});

app.listen(port, () => {
    console.log(`🚀 miTch Pilot Verifier listening at http://localhost:${port}`);
    console.log(`👉 Waiting for Wallet presentations on /present`);
});
