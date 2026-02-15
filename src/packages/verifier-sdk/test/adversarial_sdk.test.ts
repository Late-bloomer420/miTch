import { describe, test, expect, beforeAll } from 'vitest';
import { VerifierSDK } from '../src/index';
import {
    generateKeyPair,
    EphemeralKey,
    canonicalStringify,
    encrypt,
    wrapKeyForRecipient
} from '@mitch/shared-crypto';

describe('Adversarial Tests: Verifier SDK Binding (V1-V3)', () => {
    let verifierKeysA: CryptoKeyPair;
    let verifierKeysB: CryptoKeyPair;
    const DID_A = 'did:mitch:verifier:A';
    const DID_B = 'did:mitch:verifier:B';

    beforeAll(async () => {
        // RSA-OAEP keys for verifiers
        verifierKeysA = await (globalThis as any).crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["decrypt", "unwrapKey", "encrypt", "wrapKey"]
        );
        verifierKeysB = await (globalThis as any).crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["decrypt", "unwrapKey", "encrypt", "wrapKey"]
        );
    });

    test('V1: Replay Attack - pkg for Verifier A is rejected by Verifier B (AAD Binding)', async () => {
        const sdkB = new VerifierSDK({ privateKey: verifierKeysB.privateKey, verifierDid: DID_B });

        // 1. Wallet generates package for A
        const ephemeralKey = await EphemeralKey.create();
        const nonce = 'session-nonce-123';
        const decisionId = 'dec-456';

        // Signed Proof Artifact (T-12)
        const proofKeys = await generateKeyPair();
        const vp = { metadata: { nonce, decision_id: decisionId }, disclosure: { isOver18: true } };
        const proofPublicJWK = await (globalThis as any).crypto.subtle.exportKey('jwk', proofKeys.publicKey);
        const signature = await (globalThis as any).crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            proofKeys.privateKey,
            new TextEncoder().encode(canonicalStringify(vp))
        );
        const signatureHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

        const artifact = { vp, proof: { alg: 'ES256', signature: signatureHex, public_key: proofPublicJWK } };

        // Bind to DID_A
        const aadForA = new TextEncoder().encode(canonicalStringify({
            decision_id: decisionId,
            nonce,
            verifier_did: DID_A
        }));

        const ciphertext = await ephemeralKey.encrypt(JSON.stringify(artifact), aadForA);
        const encryptedKey = await ephemeralKey.sealToRecipient(verifierKeysA.publicKey);

        const pkgForA = {
            ciphertext,
            aad_context: { decision_id: decisionId, nonce, verifier_did: DID_A },
            recipient: { encrypted_key: encryptedKey }
        };

        // 2. Attack: Send pkgForA to Verifier B
        // This should fail because SDK B uses DID_B to reconstruct AAD
        await expect(sdkB.verifyPresentation(JSON.stringify(pkgForA)))
            .rejects.toThrow(/SECURITY_VIOLATION/i);
    });

    test('V2: Recipient Binding Manipulation - changing verifier_did in context is detected', async () => {
        const sdkA = new VerifierSDK({ privateKey: verifierKeysA.privateKey, verifierDid: DID_A });

        // Create valid package for A
        const ephemeralKey = await EphemeralKey.create();
        const aad = new TextEncoder().encode(canonicalStringify({ decision_id: 'd1', nonce: 'n1', verifier_did: DID_A }));
        const ciphertext = await ephemeralKey.encrypt(JSON.stringify({ vp: { metadata: { nonce: 'n1' } }, proof: {} }), aad);
        const encryptedKey = await ephemeralKey.sealToRecipient(verifierKeysA.publicKey);

        const pkg = {
            ciphertext,
            aad_context: { decision_id: 'd1', nonce: 'n1', verifier_did: DID_A },
            recipient: { encrypted_key: encryptedKey }
        };

        // Attack: Tamper with verifier_did in context to point somewhere else
        pkg.aad_context.verifier_did = 'did:mitch:evil-verifier';

        await expect(sdkA.verifyPresentation(JSON.stringify(pkg)))
            .rejects.toThrow(/addressed to different verifier/i);
    });

    test('V3: Integrity Tamper - modifying ciphertext results in decryption failure', async () => {
        const sdkA = new VerifierSDK({ privateKey: verifierKeysA.privateKey, verifierDid: DID_A });

        const ephemeralKey = await EphemeralKey.create();
        const aad = new TextEncoder().encode(canonicalStringify({ decision_id: 'd1', nonce: 'n1', verifier_did: DID_A }));
        const ciphertext = await ephemeralKey.encrypt(JSON.stringify({}), aad);
        const encryptedKey = await ephemeralKey.sealToRecipient(verifierKeysA.publicKey);

        const pkg = {
            ciphertext,
            aad_context: { decision_id: 'd1', nonce: 'n1', verifier_did: DID_A },
            recipient: { encrypted_key: encryptedKey }
        };

        // Attack: Flip a bit in ciphertext
        const tamperedCiphertext = pkg.ciphertext.substring(0, 10) + (pkg.ciphertext[10] === 'A' ? 'B' : 'A') + pkg.ciphertext.substring(11);
        pkg.ciphertext = tamperedCiphertext;

        await expect(sdkA.verifyPresentation(JSON.stringify(pkg)))
            .rejects.toThrow(); // AES-GCM tag mismatch
    });
});
