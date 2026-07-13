/**
 * Cryptographic credential signature verification tests (F-14 / SECURE-1)
 *
 * RED phase: these tests assert the NEW async behaviour and signaturesVerified field.
 * They FAIL before the implementation is wired.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verifyAuthorizationResponse } from '../response-verifier';
import {
    issueSDJWTVC,
    createKeyBindingJWT,
    buildCNFClaim,
} from '@askmi/shared-crypto';
import type { PresentationDefinition, AuthorizationResponse, PresentationSubmission } from '@askmi/oid4vp';

// ─── Key generation helper ────────────────────────────────────────────────────

/** Generate an extractable ECDSA P-256 key pair for test use. */
async function generateTestKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, // extractable so we can pass the private key to issueSDJWTVC
        ['sign', 'verify']
    );
}

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const DEFINITION: PresentationDefinition = {
    id: 'age-pd',
    input_descriptors: [
        {
            id: 'age-descriptor',
            constraints: {
                limit_disclosure: 'required',
                fields: [{ path: ['$.credentialSubject.over18'] }],
            },
        },
    ],
};

const VERIFIER_AUD = 'https://verifier.askmi.demo';
const NONCE = `crypto-test-nonce-${Date.now()}`;

let issuerKeyPair: CryptoKeyPair;
let wrongKeyPair: CryptoKeyPair;
let holderKeyPair: CryptoKeyPair;

/** A minimal valid SD-JWT VC payload per draft-11 */
function vcPayload(cnf?: { jwk: JsonWebKey }) {
    return {
        iss: 'https://issuer.askmi.demo',
        vct: 'https://credentials.askmi.demo/age',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        sub: 'did:example:holder',
        ...(cnf ? { cnf } : {}),
    };
}

function buildSub(defId = 'age-pd'): PresentationSubmission {
    return {
        id: 'sub-crypto-1',
        definition_id: defId,
        descriptor_map: [{ id: 'age-descriptor', format: 'sd-jwt', path: '$' }],
    };
}

function buildResp(vpToken: string, nonce = NONCE): AuthorizationResponse {
    return {
        vp_token: vpToken,
        presentation_submission: buildSub(),
        state: 'state-crypto',
    };
    void nonce; // nonce passed as opts.expectedNonce
}

beforeAll(async () => {
    issuerKeyPair = await generateTestKeyPair();
    wrongKeyPair = await generateTestKeyPair();
    holderKeyPair = await generateTestKeyPair();
});

// ─── Test 1: valid signed credential + correct resolver → signaturesVerified:true ─

describe('verifyAuthorizationResponse — crypto verification', () => {
    it('1) valid signed SD-JWT VC + correct issuer key → valid:true, signaturesVerified:true', async () => {
        const issuerJwt = await issueSDJWTVC(vcPayload(), issuerKeyPair.privateKey);
        // SD-JWT compact (no disclosures, no KB-JWT): "header.payload.sig~"
        const credential = `${issuerJwt}~`;

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential),
            expectedNonce: `nonce-valid-${Date.now()}`,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: true,
            resolveIssuerKey: async (_iss: string) => issuerKeyPair.publicKey,
            expectedAudience: VERIFIER_AUD,
        });

        expect(result.valid).toBe(true);
        expect(result.signaturesVerified).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('2a) wrong issuer key → fail-closed (valid:false, signaturesVerified:false)', async () => {
        const issuerJwt = await issueSDJWTVC(vcPayload(), issuerKeyPair.privateKey);
        const credential = `${issuerJwt}~`;

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential),
            expectedNonce: `nonce-wrongkey-${Date.now()}`,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: true,
            // resolver returns the WRONG public key
            resolveIssuerKey: async (_iss: string) => wrongKeyPair.publicKey,
            expectedAudience: VERIFIER_AUD,
        });

        expect(result.valid).toBe(false);
        expect(result.signaturesVerified).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
    });

    it('2b) resolver returns null → fail-closed (valid:false, signaturesVerified:false)', async () => {
        const issuerJwt = await issueSDJWTVC(vcPayload(), issuerKeyPair.privateKey);
        const credential = `${issuerJwt}~`;

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential),
            expectedNonce: `nonce-nullkey-${Date.now()}`,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: true,
            resolveIssuerKey: async (_iss: string) => null,
            expectedAudience: VERIFIER_AUD,
        });

        expect(result.valid).toBe(false);
        expect(result.signaturesVerified).toBe(false);
        expect(result.errors.some((e) => e.includes('no key'))).toBe(true);
    });

    it('3) verifyCredentialSignatures:true, no resolveIssuerKey → fail-closed', async () => {
        const issuerJwt = await issueSDJWTVC(vcPayload(), issuerKeyPair.privateKey);
        const credential = `${issuerJwt}~`;

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential),
            expectedNonce: `nonce-noResolver-${Date.now()}`,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: true,
            // no resolveIssuerKey
            expectedAudience: VERIFIER_AUD,
        });

        expect(result.valid).toBe(false);
        expect(result.signaturesVerified).toBe(false);
        expect(result.errors.some((e) => e.includes('no issuer key resolver'))).toBe(true);
    });

    it('4) KB-JWT segment present + valid holder binding → signaturesVerified:true', async () => {
        const cnf = await buildCNFClaim(holderKeyPair.publicKey);
        const issuerJwt = await issueSDJWTVC(vcPayload(cnf as { jwk: JsonWebKey }), issuerKeyPair.privateKey);
        // SD-JWT with one fake disclosure and a KB-JWT appended
        const sdJwtWithDisclosures = `${issuerJwt}~fakedisc~`;
        const kbJwt = await createKeyBindingJWT(
            { aud: VERIFIER_AUD, nonce: NONCE, sdJwtWithDisclosures },
            holderKeyPair.privateKey
        );
        const credential = `${sdJwtWithDisclosures}${kbJwt}`;

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential, NONCE),
            expectedNonce: NONCE,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: true,
            resolveIssuerKey: async (_iss: string) => issuerKeyPair.publicKey,
            expectedAudience: VERIFIER_AUD,
        });

        expect(result.valid).toBe(true);
        expect(result.signaturesVerified).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('5) KB-JWT signed by wrong holder key → fail-closed', async () => {
        const cnf = await buildCNFClaim(holderKeyPair.publicKey);
        const issuerJwt = await issueSDJWTVC(vcPayload(cnf as { jwk: JsonWebKey }), issuerKeyPair.privateKey);
        const sdJwtWithDisclosures = `${issuerJwt}~`;
        // KB-JWT signed by a WRONG key
        const kbJwt = await createKeyBindingJWT(
            { aud: VERIFIER_AUD, nonce: NONCE, sdJwtWithDisclosures },
            wrongKeyPair.privateKey  // WRONG key
        );
        const credential = `${sdJwtWithDisclosures}${kbJwt}`;

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential, NONCE),
            expectedNonce: NONCE,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: true,
            resolveIssuerKey: async (_iss: string) => issuerKeyPair.publicKey,
            expectedAudience: VERIFIER_AUD,
        });

        expect(result.valid).toBe(false);
        expect(result.signaturesVerified).toBe(false);
    });

    it('6) verifyCredentialSignatures:false → structural behaviour preserved, signaturesVerified:false', async () => {
        // Simple JWT-like token (not crypto-verified)
        const credential = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig';

        const result = await verifyAuthorizationResponse({
            response: buildResp(credential),
            expectedNonce: `nonce-noverify-${Date.now()}`,
            expectedState: 'state-crypto',
            definition: DEFINITION,
            skipNonceCheck: true,
            verifyCredentialSignatures: false,
        });

        // Structural checks still apply (credential is non-empty → valid)
        expect(result.valid).toBe(true);
        expect(result.signaturesVerified).toBe(false);
    });
});
