/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, beforeAll } from 'vitest';
import {
    buildHAIPPresentationDefinition,
    issueVerifierAttestation,
    validateVerifierAttestation,
    validateHAIPRequest,
    encryptDirectPostResponse,
    decryptDirectPostResponse,
} from '../haip';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

let trustAnchorPrivKey: CryptoKey;
let trustAnchorPubKey: CryptoKey;
let verifierPrivKey: CryptoKey;
let verifierPubKey: CryptoKey;

const TRUST_ANCHOR_ISS = 'https://trust-anchor.example.com';
const VERIFIER_CLIENT_ID = 'https://verifier.example.com';
const REDIRECT_URI = 'https://verifier.example.com/callback';

beforeAll(async () => {
    const taPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    trustAnchorPrivKey = taPair.privateKey;
    trustAnchorPubKey = taPair.publicKey;

    const vPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    verifierPrivKey = vPair.privateKey;
    verifierPubKey = vPair.publicKey;
});

// ─── E-13.1: Presentation Definition ─────────────────────────────────────────

describe('HAIP Presentation Definition', () => {
    it('builds a PD with limit_disclosure=required', () => {
        const pd = buildHAIPPresentationDefinition('haip-test-pd', [
            { format: 'vc+sd-jwt', claimPaths: ['$.age_over_18'], purpose: 'Age Verification' },
        ]);
        expect(pd.id).toBe('haip-test-pd');
        expect(pd.input_descriptors).toHaveLength(1);
        expect(pd.input_descriptors[0].constraints?.limit_disclosure).toBe('required');
    });

    it('builds a PD with multiple descriptors', () => {
        const pd = buildHAIPPresentationDefinition('multi-pd', [
            { format: 'vc+sd-jwt', claimPaths: ['$.age_over_18'] },
            { format: 'vc+sd-jwt', claimPaths: ['$.given_name', '$.family_name'] },
        ]);
        expect(pd.input_descriptors).toHaveLength(2);
        pd.input_descriptors.forEach(d => {
            expect(d.constraints?.limit_disclosure).toBe('required');
        });
    });

    it('enforces limit_disclosure=required on all descriptors', () => {
        const pd = buildHAIPPresentationDefinition('id', [
            { format: 'vc+sd-jwt', claimPaths: ['$.foo'] },
        ]);
        expect(pd.input_descriptors[0].constraints?.limit_disclosure).toBe('required');
    });
});

// ─── E-13.2: Verifier Attestation ────────────────────────────────────────────

describe('Verifier Attestation JWT', () => {
    it('issues and validates a verifier attestation', async () => {
        const jwt = await issueVerifierAttestation({
            iss: TRUST_ANCHOR_ISS,
            verifierClientId: VERIFIER_CLIENT_ID,
            verifierPublicKey: verifierPubKey,
            redirectUris: [REDIRECT_URI],
        }, trustAnchorPrivKey);

        const result = await validateVerifierAttestation(jwt, trustAnchorPubKey, {
            expectedClientId: VERIFIER_CLIENT_ID,
        });
        expect(result.ok).toBe(true);
        expect(result.payload?.sub).toBe(VERIFIER_CLIENT_ID);
        expect(result.payload?.cnf.jwk.kty).toBe('EC');
    });

    it('rejects attestation from unknown trust anchor', async () => {
        const unknownPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
        );
        const jwt = await issueVerifierAttestation({
            iss: TRUST_ANCHOR_ISS,
            verifierClientId: VERIFIER_CLIENT_ID,
            verifierPublicKey: verifierPubKey,
        }, unknownPair.privateKey);

        const result = await validateVerifierAttestation(jwt, trustAnchorPubKey);
        expect(result.ok).toBe(false);
        expect(result.errors[0]).toMatch(/verification failed/);
    });

    it('rejects attestation with wrong client_id', async () => {
        const jwt = await issueVerifierAttestation({
            iss: TRUST_ANCHOR_ISS,
            verifierClientId: VERIFIER_CLIENT_ID,
            verifierPublicKey: verifierPubKey,
        }, trustAnchorPrivKey);

        const result = await validateVerifierAttestation(jwt, trustAnchorPubKey, {
            expectedClientId: 'https://other-verifier.example.com',
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('client_id mismatch'))).toBe(true);
    });
});

// ─── E-13.3: HAIP Request Validation ─────────────────────────────────────────

describe('HAIP Authorization Request Validation', () => {
    async function buildHAIPRequest() {
        const attestation = await issueVerifierAttestation({
            iss: TRUST_ANCHOR_ISS,
            verifierClientId: VERIFIER_CLIENT_ID,
            verifierPublicKey: verifierPubKey,
        }, trustAnchorPrivKey);

        const pd = buildHAIPPresentationDefinition('haip-pd', [
            { format: 'vc+sd-jwt', claimPaths: ['$.age_over_18'] },
        ]);

        return {
            response_type: 'vp_token',
            client_id: VERIFIER_CLIENT_ID,
            client_id_scheme: 'verifier_attestation',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
            client_assertion: attestation,
            redirect_uri: REDIRECT_URI,
            response_mode: 'direct_post.jwt',
            nonce: 'test-haip-nonce',
            presentation_definition: pd,
        };
    }

    it('validates a correct HAIP request', async () => {
        const req = await buildHAIPRequest();
        const result = await validateHAIPRequest(req, trustAnchorPubKey);
        expect(result.ok).toBe(true);
        expect(result.verifierPayload?.sub).toBe(VERIFIER_CLIENT_ID);
    });

    it('rejects request without verifier_attestation scheme', async () => {
        const req = await buildHAIPRequest();
        const result = await validateHAIPRequest(
            { ...req, client_id_scheme: 'redirect_uri' },
            trustAnchorPubKey
        );
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('verifier_attestation'))).toBe(true);
    });

    it('rejects request without direct_post.jwt response mode', async () => {
        const req = await buildHAIPRequest();
        const result = await validateHAIPRequest(
            { ...req, response_mode: 'direct_post' },
            trustAnchorPubKey
        );
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('direct_post.jwt'))).toBe(true);
    });
});

// ─── E-13.4: direct_post.jwt Encrypted Response ───────────────────────────────

describe('direct_post.jwt Response Encryption', () => {
    it('encrypts and decrypts a VP token response', async () => {
        // Need ECDH key pair for encryption (ECDH-ES)
        const ecdhPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
        );

        const vpToken = 'eyJhbGciOiJFUzI1NiJ9.payload.sig~disclosure~';
        const encrypted = await encryptDirectPostResponse(vpToken, ecdhPair.publicKey);
        expect(encrypted.response).toMatch(/^eyJ/); // JWE compact

        const decrypted = await decryptDirectPostResponse(encrypted.response, ecdhPair.privateKey);
        expect(decrypted.vp_token).toBe(vpToken);
    });
});
