import { WalletService } from '../../apps/wallet-pwa/src/services/WalletService';

async function testDeepLinkFlow() {
    console.log('🧪 Testing T-88 Deep Link Parsing...');

    // 1. Simulate Verifier Client KeyGen (Copy-Paste from VerifierClient logic roughly)
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "wrapKey"]
    );
    const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

    // 2. Construct Link
    const sessionId = crypto.randomUUID();
    const nonce = crypto.randomUUID();
    const pubB64 = btoa(JSON.stringify(pubJwk));

    const validLink = `mitch://present?nonce=${nonce}&session=${sessionId}&pub=${pubB64}`;
    console.log('🔗 Generated Link:', validLink.substring(0, 50) + '...');

    // 3. Parse in WalletService
    const wallet = new WalletService();
    // Helper to bypass checking other state if parse is stateless
    const request = await wallet.parseDeepLinkRequest(validLink);

    if (request) {
        console.log('✅ Parsed Successfully!');
        console.log('   DID:', request.verifierDid);
        console.log('   Key Present:', !!request.ephemeralResponseKey);

        if (request.ephemeralResponseKey) {
            const keyAlgo = request.ephemeralResponseKey.algorithm;
            console.log('   Key Algo:', keyAlgo.name); // Should be RSA-OAEP

            // Verify it is a CryptoKey object
            if (request.ephemeralResponseKey.toString() === '[object CryptoKey]') {
                console.log('   Type Check: PASSED');
            }
        }
    } else {
        console.error('❌ Parse Failed!');
    }
}

// execute if running directly (via ts-node or similar in test env)
// testDeepLinkFlow();
export { testDeepLinkFlow };
