export interface VerifierSession {
    sessionId: string;
    nonce: string;
    publicKey: JsonWebKey;
    privateKey: JsonWebKey; // Ephemeral! Stored in memory only.
    deepLink: string;
}

export class VerifierClient {
    /**
     * Generates an ephemeral session for a single verification.
     * Keys are held in memory and lost on refresh (Privacy Feature: "Crypto-Shredding by Default").
     */
    public async generateSession(
        baseUrl: string = 'http://localhost:3000',
        reason: string = 'Age Verification',
        verifierDid: string = 'did:mitch:verifier-liquor-store'
    ): Promise<VerifierSession> {
        // 1. Generate Ephemeral Key Pair (RSA-OAEP-256)
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        );

        // 2. Export Keys (JWK)
        const publicKey = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey) as JsonWebKey;
        const privateKey = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey) as JsonWebKey;

        // 3. Create Session ID & Nonce
        const sessionId = crypto.randomUUID();
        const nonce = crypto.randomUUID();

        // 4. Clean JWK for transport (remove optional fields if excessive)
        // Wallet needs 'n', 'e', 'kty', 'alg'
        const cleanPublicJwk = {
            kty: publicKey.kty,
            n: publicKey.n,
            e: publicKey.e,
            alg: "RSA-OAEP-256",
            ext: true,
            key_ops: ["encrypt", "wrapKey"]
        };

        // 5. Construct QR Code / Deep Link
        // mitch://present?aud=<url>&nonce=<nonce>&pub=<base64-jwk>
        // Note: We encode the PUBLIC KEY directly in the URL to avoid needing a backend registry.
        // This is "Self-Certifying" for ephemeral sessions.
        const pubKeyString = JSON.stringify(cleanPublicJwk);
        const b64PubKey = btoa(pubKeyString);

        // The wallet will post the result back to this page (or a specific callback)
        // ideally via a postMessage or a redirected callback. 
        // For the Pilot, we might use a simple HTTP POST to a lightweight relay or logic.
        // Wait, "Zero Backend"?
        // If Zero Backend, the Wallet must display the result on its screen, OR we need a way to pass data back.
        // OPTION A: Wallet scans QR -> User sees "Verified" on Wallet -> Show Result on Wallet.
        // OPTION B: Wallet scans QR -> Sends data to a temporary relay -> Browser polls relay.
        // OPTION C: P2P (WebRTC)? Too complex.

        // ARCHITECTURE DECISION FOR SME KIT:
        // We will use a "Local Loopback" or "Display verification code" approach if purely offline,
        // BUT for a "Liquor Store" experience, the Shop Owner wants to see it on THEIR screen.
        // Since we can't spin up a server, we likely need a very dumb relay (e.g. Supabase Realtime or similar free tier).
        // OR: The wallet simply shows a big green checkmark.

        // FOR NOW: We implement the Client side of the "Protocol".
        // Let's assume the wallet sends the response to a `callbackUrl` provided in the QR.
        // If the shop owner has no backend, maybe they rely on the Wallet's UI?
        // NO, the requirement is "Liquor Store Integration".

        // Let's stick to the interface.
        const deepLink = `mitch://present?nonce=${nonce}&session=${sessionId}&pub=${b64PubKey}`;

        return {
            sessionId,
            nonce,
            publicKey: cleanPublicJwk,
            privateKey,
            deepLink
        };
    }

    /**
     * Decrypts a presentation package received from the Wallet.
     */
    public async verifyResponse(
        encryptedPackage: string,
        session: VerifierSession
    ): Promise<any> {
        // 1. Parse JWE Compact Serialization (header.encryptedKey.iv.ciphertext.tag)
        const parts = encryptedPackage.split('.');
        if (parts.length !== 5) {
            throw new Error("Invalid JWE format");
        }

        const [b64Header, b64EncKey, b64Iv, b64Ciphertext, b64Tag] = parts;

        // Helper: Base64Url to Uint8Array
        const b64UrlToBuffer = (b64: string) => {
            const padding = '='.repeat((4 - b64.length % 4) % 4);
            const base64 = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
            const rawData = atob(base64);
            return Uint8Array.from(rawData, c => c.charCodeAt(0));
        };

        // 2. Import Private Key (RSA-OAEP)
        const privKey = await window.crypto.subtle.importKey(
            "jwk",
            session.privateKey,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );

        // 3. Decrypt the Content Encryption Key (CEK)
        const encKey = b64UrlToBuffer(b64EncKey);
        const cekBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privKey,
            encKey
        );

        // 4. Import CEK (AES-GCM)
        const cek = await window.crypto.subtle.importKey(
            "raw",
            cekBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        // 5. Decrypt Content
        const iv = b64UrlToBuffer(b64Iv);
        const ciphertext = b64UrlToBuffer(b64Ciphertext);
        const tag = b64UrlToBuffer(b64Tag);

        // WebCrypto expects tag appended to ciphertext
        const combinedData = new Uint8Array(ciphertext.length + tag.length);
        combinedData.set(ciphertext);
        combinedData.set(tag, ciphertext.length);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            cek,
            combinedData
        );

        const decryptedJson = new TextDecoder().decode(decryptedBuffer);
        return JSON.parse(decryptedJson);
    }
}
