
import { describe, it, expect, beforeAll } from 'vitest';
import { VerifierSDK } from '../src/VerifierSDK';
import {
    VerifierError,
    TransportParseError,
    KeyUnwrapError,
    DecryptError,
    AADValidationError,
    ReplayDetectedError,
    ProofSignatureError
} from '../src/types';
import {
    generateKeyPair,
    generateSymmetricKey,
    EphemeralKey,
    canonicalStringify,
    encrypt
} from '@mitch/shared-crypto';

// Polyfill for Node environment if needed (Vitest usually handles this but explicit is safe)
const crypto = globalThis.crypto;

describe('VerifierSDK Attack Vectors', () => {
    let verifierSDK: VerifierSDK;
    let verifierKeys: CryptoKeyPair;
    const VERIFIER_DID = 'did:example:verifier-1';

    // Mock Replay Cache
    const seenNonces = new Set<string>();
    const mockReplayCheck = async (nonce: string, decisionId: string) => {
        if (seenNonces.has(nonce)) return true;
        seenNonces.add(nonce);
        return false;
    };

    beforeAll(async () => {
        // Generate Verifier RSA Keys (RSA-OAEP)
        verifierKeys = await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["decrypt", "unwrapKey", "encrypt", "wrapKey"]
        );

        verifierSDK = new VerifierSDK({
            privateKey: verifierKeys.privateKey,
            verifierDid: VERIFIER_DID,
            replayCheck: mockReplayCheck
        });
    });

    /**
     * Helper to Create a Valid Transport Package
     */
    async function createValidPackage(overrides: any = {}) {
        const decisionId = overrides.decisionId || 'dec-123';
        const nonce = overrides.nonce || crypto.randomUUID();
        const verifierDid = overrides.verifierDid || VERIFIER_DID;

        // 1. Proof Key
        const proofKeys = await generateKeyPair();
        const proofPubJwk = await crypto.subtle.exportKey('jwk', proofKeys.publicKey);

        // 2. VP Payload
        const vpPayload = {
            metadata: {
                type: 'VP',
                decision_id: decisionId,
                timestamp: Date.now(),
                nonce: nonce,
                ...overrides.metadata
            },
            content: 'valid-credential-data'
        };

        // 3. Sign
        const payloadStr = canonicalStringify(vpPayload);
        const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            proofKeys.privateKey,
            new TextEncoder().encode(payloadStr)
        );
        const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

        const artifact = {
            vp: vpPayload,
            proof: {
                alg: 'ES256',
                signature: sigHex,
                public_key: proofPubJwk
            }
        };

        // 4. Encrypt with Ephemeral Key
        const ephemeralKey = await EphemeralKey.create();
        const aadContext = {
            decision_id: decisionId,
            nonce: nonce,
            verifier_did: verifierDid
        };

        // AAD Construction must match SDK exaclty
        const aadBytes = new TextEncoder().encode(
            canonicalStringify(aadContext)
        );

        // Manually encrypt if overrides need tampering (e.g. wrong AAD for encryption vs artifact)
        // Check if override cipher logic is needed
        let ciphertext: string;
        if (overrides.badKey) {
            const badKey = await EphemeralKey.create(); // Different key
            ciphertext = await badKey.encrypt(JSON.stringify(artifact), aadBytes);
        } else if (overrides.tamperedCiphertext) {
            const validCt = await ephemeralKey.encrypt(JSON.stringify(artifact), aadBytes);
            // Flip a bit in the ciphertext suffix (keeping IV intact)
            const raw = atob(validCt);
            const sub = raw.substring(0, raw.length - 5) + 'X' + raw.substring(raw.length - 4);
            ciphertext = btoa(sub);
        } else if (overrides.wrongAadForEncryption) {
            const badAad = new TextEncoder().encode('bad-aad');
            ciphertext = await ephemeralKey.encrypt(JSON.stringify(artifact), badAad);
        } else {
            ciphertext = await ephemeralKey.encrypt(JSON.stringify(artifact), aadBytes);
        }

        // 5. Wrap Key
        const recipientPubKey = overrides.wrongRecipientKey
            ? (await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['wrapKey'])).publicKey
            : verifierKeys.publicKey;

        const encryptedKey = await ephemeralKey.sealToRecipient(recipientPubKey);

        return JSON.stringify({
            ciphertext,
            aad_context: aadContext,
            recipient: {
                header: { kid: 'test-1' },
                encrypted_key: encryptedKey
            }
        });
    }

    it('should verify a valid presentation', async () => {
        const pkg = await createValidPackage();
        const result = await verifierSDK.verifyPresentation(pkg);
        expect(result.proof.verified).toBe(true);
        expect(result.vp.content).toBe('valid-credential-data');
    });

    it('should REJECT incorrect Verifier DID (Address Check)', async () => {
        // Encrypt FOR a different verifier
        const pkg = await createValidPackage({ verifierDid: 'did:example:WRONG_TARGET' });
        // The SDK checks pkg.aad_context.verifier_did vs config.verifierDid
        // Here we spoof the AAD context to MATCH the config, but the ENCRYPTION was done with WRONG AAD?
        // Wait, if I change aad_context in the package, the DECRYPTION will fail because AAD input to GCM is derived from it.

        // Case A: Package AAD says "WRONG", SDK config says "RIGHT". SDK should throw before decrypt.
        // Let's modify the JSON string after creation to simulate MITM redirecting a packet
        const validPkgJson = await createValidPackage({ verifierDid: VERIFIER_DID }); // Valid for 'verifier-1'
        const validPkg = JSON.parse(validPkgJson);

        // Attacker changes address label
        validPkg.aad_context.verifier_did = 'did:example:verifier-2';

        // The SDK is configured as 'verifier-1'. 
        // 1. SDK Check: aad.verifier_did !== config.did -> Throw AADValidationError
        // BUT wait, in this test I want to prove fail if the PACKAGE says "verifier-2" (e.g. sent by mistake to verifier-1).

        // Actually, the test case "REJECT incorrect Verifier DID" usually means:
        // The WALLET encrypted it for 'verifier-2'. 'verifier-1' receives it.
        // 'verifier-1' SDK checks AAD. "This is for verifier-2, not me." -> Throw.

        const hijackedPkg = JSON.stringify(validPkg);

        // We need to re-instantiate SDK with 'did:example:verifier-1' (default)
        // The hijacked Package says 'verifier-2'

        // Wait, if I modify validPkg.aad_context, decrpytion will fail later too.
        // But SDK should catch it EARLY at the "Address Verification" step.

        await expect(verifierSDK.verifyPresentation(hijackedPkg))
            .rejects.toThrow(AADValidationError);
    });

    it('should REJECT tampering with Ciphertext', async () => {
        const pkg = await createValidPackage({ tamperedCiphertext: true });
        await expect(verifierSDK.verifyPresentation(pkg))
            .rejects.toThrow(DecryptError);
    });

    it('should REJECT tampering with AAD (Context)', async () => {
        // Generate valid package
        const validJson = await createValidPackage();
        const pkg = JSON.parse(validJson);

        // Attacker modifies nonce in open text (aad_context) to try to fool replay check?
        pkg.aad_context.nonce = 'modified-nonce';

        // Now SDK reconstructs AAD using 'modified-nonce'.
        // GCM Decrypt uses this new AAD.
        // But ciphertext was authenticated against ORIGINAL nonce.
        // GCM Decrypt should FAIL.

        await expect(verifierSDK.verifyPresentation(JSON.stringify(pkg)))
            .rejects.toThrow(DecryptError);
    });

    it('should REJECT Replay Attacks', async () => {
        const pkg = await createValidPackage();

        // First pass: OK
        await verifierSDK.verifyPresentation(pkg);

        // Second pass: ReplayDetected
        await expect(verifierSDK.verifyPresentation(pkg))
            .rejects.toThrow(ReplayDetectedError);
    });

    it('should REJECT Invalid Proof Signature', async () => {
        // 1. Create VALID package (signed correctly)
        const validJson = await createValidPackage();
        const pkg = JSON.parse(validJson);

        // 2. Decrypt it (we're simulating an attacker who can decrypt their OWN packet, 
        //    modify it, and re-encrypt it, hoping the server won't check the signature)
        //    (In reality, an attacker typically intercepts, but let's assume valid key access for test mechanics)
        const ephemeralKey = await EphemeralKey.create();
        const aadBytes = new TextEncoder().encode(
            canonicalStringify({
                decision_id: pkg.aad_context.decision_id,
                nonce: pkg.aad_context.nonce,
                verifier_did: pkg.aad_context.verifier_did
            })
        );

        // For test simplicity, we regenerate the artifact rather than decrypting the one above
        // because we don't have the ephemeral key handle from createValidPackage exposed.
        const proofKeys = await generateKeyPair();
        const proofPubJwk = await crypto.subtle.exportKey('jwk', proofKeys.publicKey);

        const vpPayload = {
            metadata: { type: 'VP', timestamp: Date.now() },
            content: 'valid-data'
        };

        // SIGN the valid payload
        const payloadStr = canonicalStringify(vpPayload);
        const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            proofKeys.privateKey,
            new TextEncoder().encode(payloadStr)
        );
        const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

        // 3. TAMPER with the VP content AFTER signing
        // The artifact contains the SIGNATURE of 'valid-data', but the CONTENT is 'TAMPERED-DATA'
        const tamperedArtifact = {
            vp: { ...vpPayload, content: 'TAMPERED-DATA' },
            proof: {
                alg: 'ES256',
                signature: sigHex, // Signature of VALID data
                public_key: proofPubJwk
            }
        };

        // 4. Encrypt the TAMPERED artifact
        // The encryption (GCM) is valid, so it passes decryption.
        // But the inner ECDSA check should fail because signature doesn't match content.
        const tamperedCiphertext = await ephemeralKey.encrypt(JSON.stringify(tamperedArtifact), aadBytes);
        const encryptedKey = await ephemeralKey.sealToRecipient(verifierKeys.publicKey);

        const tamperedPkg = {
            ciphertext: tamperedCiphertext,
            aad_context: pkg.aad_context,
            recipient: { header: { kid: 'test' }, encrypted_key: encryptedKey }
        };

        await expect(verifierSDK.verifyPresentation(JSON.stringify(tamperedPkg)))
            .rejects.toThrow(ProofSignatureError);
    });
});
