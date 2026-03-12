/**
 * VerifierSDK — edge-case coverage
 *
 * Complements sdk.test.ts by covering paths not yet tested:
 * - TransportParseError on malformed JSON
 * - TransportParseError on missing required fields
 * - KeyUnwrapError when encrypted_key is garbage / wrong key
 * - TokenExpiredError when VP timestamp is stale (> 5 min)
 * - TokenExpiredError when VP timestamp is too far in the future (> 30 s)
 * - TokenExpiredError when validUntil is in the past
 * - createRequest() return shape
 * - VerifierError / error taxonomy (code + name fields)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { VerifierSDK } from '../src/VerifierSDK.js';
import {
    TransportParseError,
    KeyUnwrapError,
    TokenExpiredError,
    VerifierError,
} from '../src/types.js';
import { generateKeyPair, EphemeralKey, canonicalStringify } from '@mitch/shared-crypto';

const VERIFIER_DID = 'did:example:edge-verifier';

let verifierKeys: CryptoKeyPair;
let sdk: VerifierSDK;

// Track nonces so we don't replay
const usedNonces = new Set<string>();
const noReplay = async (nonce: string) => {
    if (usedNonces.has(nonce)) return true;
    usedNonces.add(nonce);
    return false;
};

beforeAll(async () => {
    verifierKeys = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey'],
    );
    sdk = new VerifierSDK({ privateKey: verifierKeys.privateKey, verifierDid: VERIFIER_DID, replayCheck: noReplay });
});

// ─── helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal valid transport package string (optionally offset timestamp) */
async function buildPackage(opts: {
    timestampOffset?: number; // ms relative to now
    validUntil?: number;      // absolute ms epoch
    decisionId?: string;
    nonce?: string;
} = {}): Promise<string> {
    const nonce = opts.nonce ?? crypto.randomUUID();
    const decisionId = opts.decisionId ?? 'dec-edge';
    const timestamp = Date.now() + (opts.timestampOffset ?? 0);

    const proofKeys = await generateKeyPair();
    const proofPubJwk = await crypto.subtle.exportKey('jwk', proofKeys.publicKey);

    const vpPayload: Record<string, unknown> = {
        metadata: { type: 'VP', decision_id: decisionId, timestamp, nonce },
        content: 'edge-case-data',
    };
    if (opts.validUntil !== undefined) {
        (vpPayload as any).validUntil = opts.validUntil;
    }

    const sig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        proofKeys.privateKey,
        new TextEncoder().encode(canonicalStringify(vpPayload)),
    );
    const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

    const artifact = {
        vp: vpPayload,
        proof: { alg: 'ES256', signature: sigHex, public_key: proofPubJwk },
    };

    const ephemeralKey = await EphemeralKey.create();
    const aadContext = { decision_id: decisionId, nonce, verifier_did: VERIFIER_DID };
    const aadBytes = new TextEncoder().encode(canonicalStringify(aadContext));
    const ciphertext = await ephemeralKey.encrypt(JSON.stringify(artifact), aadBytes);
    const encryptedKey = await ephemeralKey.sealToRecipient(verifierKeys.publicKey);

    return JSON.stringify({
        ciphertext,
        aad_context: aadContext,
        recipient: { header: { kid: 'edge-1' }, encrypted_key: encryptedKey },
    });
}

// ─── TransportParseError ──────────────────────────────────────────────────────

describe('verifyPresentation — TransportParseError', () => {
    it('throws on completely invalid JSON string', async () => {
        await expect(sdk.verifyPresentation('not valid json!!!')).rejects.toThrow(TransportParseError);
    });

    it('throws on empty string', async () => {
        await expect(sdk.verifyPresentation('')).rejects.toThrow(TransportParseError);
    });

    it('throws on missing ciphertext field', async () => {
        const pkg = JSON.stringify({
            aad_context: { decision_id: 'd', nonce: 'n', verifier_did: VERIFIER_DID },
            recipient: { header: { kid: 'k' }, encrypted_key: 'AAAA' },
            // ciphertext missing
        });
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(TransportParseError);
    });

    it('throws on missing aad_context field', async () => {
        const pkg = JSON.stringify({
            ciphertext: 'AAAA',
            recipient: { header: { kid: 'k' }, encrypted_key: 'AAAA' },
            // aad_context missing
        });
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(TransportParseError);
    });

    it('throws on missing recipient.encrypted_key', async () => {
        const pkg = JSON.stringify({
            ciphertext: 'AAAA',
            aad_context: { decision_id: 'd', nonce: 'n', verifier_did: VERIFIER_DID },
            recipient: { header: { kid: 'k' } }, // no encrypted_key
        });
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(TransportParseError);
    });

    it('TransportParseError has correct code', async () => {
        try {
            await sdk.verifyPresentation('broken');
        } catch (e) {
            expect((e as VerifierError).code).toBe('TRANSPORT_PARSE_ERROR');
        }
    });
});

// ─── KeyUnwrapError ───────────────────────────────────────────────────────────

describe('verifyPresentation — KeyUnwrapError', () => {
    it('throws when encrypted_key is garbage base64', async () => {
        const pkg = JSON.stringify({
            ciphertext: 'AAAA',
            aad_context: { decision_id: 'd', nonce: 'n', verifier_did: VERIFIER_DID },
            recipient: { header: { kid: 'k' }, encrypted_key: btoa('garbage-not-rsa') },
        });
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(KeyUnwrapError);
    });

    it('throws when package is encrypted for a different recipient key', async () => {
        // Build package encrypted for a completely different RSA key
        const wrongKeys = await crypto.subtle.generateKey(
            { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
        );
        const nonce = crypto.randomUUID();
        const decisionId = 'dec-wrong-key';
        const aadContext = { decision_id: decisionId, nonce, verifier_did: VERIFIER_DID };
        const aadBytes = new TextEncoder().encode(canonicalStringify(aadContext));
        const ephemeralKey = await EphemeralKey.create();
        const ciphertext = await ephemeralKey.encrypt('{}', aadBytes);
        // Seal to WRONG recipient key
        const encryptedKey = await ephemeralKey.sealToRecipient(wrongKeys.publicKey);

        const pkg = JSON.stringify({
            ciphertext,
            aad_context: aadContext,
            recipient: { header: { kid: 'k' }, encrypted_key: encryptedKey },
        });

        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(KeyUnwrapError);
    });

    it('KeyUnwrapError has correct code', async () => {
        const pkg = JSON.stringify({
            ciphertext: 'AAAA',
            aad_context: { decision_id: 'd', nonce: 'n', verifier_did: VERIFIER_DID },
            recipient: { header: { kid: 'k' }, encrypted_key: btoa('bad') },
        });
        try {
            await sdk.verifyPresentation(pkg);
        } catch (e) {
            expect((e as VerifierError).code).toBe('KEY_UNWRAP_ERROR');
        }
    });
});

// ─── TokenExpiredError ────────────────────────────────────────────────────────

describe('verifyPresentation — TokenExpiredError (stale timestamp)', () => {
    it('throws when VP timestamp is older than 5 minutes', async () => {
        const SIX_MIN = 6 * 60 * 1000;
        const pkg = await buildPackage({ timestampOffset: -SIX_MIN });
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(TokenExpiredError);
    });

    it('TokenExpiredError.code is TOKEN_EXPIRED', async () => {
        const pkg = await buildPackage({ timestampOffset: -(10 * 60 * 1000) });
        try {
            await sdk.verifyPresentation(pkg);
        } catch (e) {
            expect((e as VerifierError).code).toBe('TOKEN_EXPIRED');
        }
    });

    it('accepts VP timestamp within 5 minutes', async () => {
        const pkg = await buildPackage({ timestampOffset: -30_000 }); // 30 s ago
        const result = await sdk.verifyPresentation(pkg);
        expect(result.proof.verified).toBe(true);
    });
});

describe('verifyPresentation — TokenExpiredError (future timestamp)', () => {
    it('throws when VP timestamp is more than 30 s in the future', async () => {
        const pkg = await buildPackage({ timestampOffset: 60_000 }); // 60s in future
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(TokenExpiredError);
    });

    it('accepts VP timestamp within clock skew tolerance (< 30 s future)', async () => {
        const pkg = await buildPackage({ timestampOffset: 10_000 }); // 10 s future
        const result = await sdk.verifyPresentation(pkg);
        expect(result.proof.verified).toBe(true);
    });
});

describe('verifyPresentation — TokenExpiredError (validUntil)', () => {
    it('throws when validUntil is in the past', async () => {
        const pastValidUntil = Date.now() - 1000; // already expired
        const pkg = await buildPackage({ validUntil: pastValidUntil });
        await expect(sdk.verifyPresentation(pkg)).rejects.toThrow(TokenExpiredError);
    });

    it('accepts validUntil in the future', async () => {
        const futureValidUntil = Date.now() + 5 * 60 * 1000;
        const pkg = await buildPackage({ validUntil: futureValidUntil });
        const result = await sdk.verifyPresentation(pkg);
        expect(result.proof.verified).toBe(true);
    });
});

// ─── createRequest ────────────────────────────────────────────────────────────

describe('VerifierSDK.createRequest', () => {
    it('returns a VerifierRequest with correct verifierId', async () => {
        const req = await sdk.createRequest(['age', 'eu_resident'], 'age gate');
        expect(req.verifierId).toBe(VERIFIER_DID);
    });

    it('includes requested claims', async () => {
        const req = await sdk.createRequest(['over18'], 'liquor store');
        expect(req.requestedClaims).toEqual(['over18']);
    });

    it('includes purpose', async () => {
        const req = await sdk.createRequest([], 'hospital admission');
        expect(req.purpose).toBe('hospital admission');
    });

    it('returns origin field', async () => {
        const req = await sdk.createRequest([], 'test');
        expect(typeof req.origin).toBe('string');
    });

    it('multiple claims preserved in order', async () => {
        const claims = ['age', 'nationality', 'eu_resident'];
        const req = await sdk.createRequest(claims, 'multi-claim');
        expect(req.requestedClaims).toEqual(claims);
    });
});

// ─── VerifierError taxonomy ───────────────────────────────────────────────────

describe('VerifierError taxonomy', () => {
    it('TransportParseError has name "TransportParseError"', () => {
        const e = new TransportParseError('test');
        expect(e.name).toBe('TransportParseError');
        expect(e.code).toBe('TRANSPORT_PARSE_ERROR');
        expect(e instanceof VerifierError).toBe(true);
        expect(e instanceof Error).toBe(true);
    });

    it('KeyUnwrapError has name "KeyUnwrapError"', () => {
        const e = new KeyUnwrapError('test');
        expect(e.name).toBe('KeyUnwrapError');
        expect(e.code).toBe('KEY_UNWRAP_ERROR');
    });

    it('TokenExpiredError has name "TokenExpiredError"', () => {
        const e = new TokenExpiredError(60_000);
        expect(e.name).toBe('TokenExpiredError');
        expect(e.code).toBe('TOKEN_EXPIRED');
        expect(e.message).toContain('60000');
    });

    it('all errors extend VerifierError', () => {
        expect(new TransportParseError('x') instanceof VerifierError).toBe(true);
        expect(new KeyUnwrapError('x') instanceof VerifierError).toBe(true);
        expect(new TokenExpiredError(0) instanceof VerifierError).toBe(true);
    });
});
