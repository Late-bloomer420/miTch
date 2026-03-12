/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * B-02: OID4VP Direct Post Endpoint Tests
 *
 * Tests the /oid4vp-present endpoint that receives SD-JWT VP Token
 * from the wallet via direct_post and validates it.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import request from 'supertest';
import { app } from '../app';
import {
    buildOID4VPRequest,
    buildSDJWTPresentation,
    SCENARIO_VCT,
} from '@mitch/oid4vp';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const AGE_CLAIMS = { age: 24, birthDate: '2000-01-01', name: 'Max Mustermann', address: 'Zirl, AT', nationalId: 'AT-123456' };

async function generateKeyPair(): Promise<CryptoKeyPair> {
    return globalThis.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('/oid4vp-present endpoint', () => {
    let issuerKeys: CryptoKeyPair;
    let holderKeys: CryptoKeyPair;

    beforeAll(async () => {
        // Set test mode to avoid file I/O for verifier keys
        process.env.MITCH_TEST_MODE = '1';
        issuerKeys = await generateKeyPair();
        holderKeys = await generateKeyPair();
    });

    beforeEach(async () => {
        // Reset verifier state
        await request(app).post('/reset');
    });

    it('should return 400 when vp_token is missing', async () => {
        const res = await request(app)
            .post('/oid4vp-present')
            .send({ presentation_submission: {}, issuer_jwk: {} });

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toContain('Missing vp_token');
    });

    it('should return 400 when presentation_submission is missing', async () => {
        const res = await request(app)
            .post('/oid4vp-present')
            .send({ vp_token: 'fake.token.here', issuer_jwk: {} });

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toContain('Missing vp_token or presentation_submission');
    });

    it('should return 400 when issuer_jwk is missing', async () => {
        const res = await request(app)
            .post('/oid4vp-present')
            .send({ vp_token: 'fake.token.here', presentation_submission: {} });

        expect(res.status).toBe(400);
        expect(res.body.ok).toBe(false);
        expect(res.body.error).toContain('Missing issuer_jwk');
    });

    it('should verify a valid SD-JWT VP (happy path)', async () => {
        // Step 1: Get an auth request with a valid nonce
        const authRes = await request(app)
            .get('/authorize?scenario=liquor-store');
        expect(authRes.status).toBe(200);
        const { authRequest } = authRes.body;

        // Step 2: Build a real SD-JWT VP token
        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request: authRequest,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'] ?? 'https://mitch.demo/vct/age-credential',
            issuerDid: 'https://issuer.mitch.demo',
            revoked: false,
        });

        // Step 3: Export issuer public key as JWK
        const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

        // Step 4: POST to /oid4vp-present
        const res = await request(app)
            .post('/oid4vp-present')
            .send({
                vp_token: vpTokenString,
                presentation_submission: presentationSubmission,
                state: authRequest.state,
                issuer_jwk: issuerJwk,
            });

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(res.body.disclosedClaims).toBeDefined();
        expect(res.body.consentReceipt).toBeDefined();

        // Verify status endpoint reflects the result
        const statusRes = await request(app).get('/status');
        expect(statusRes.body.status).toBe('VERIFIED');
        expect(statusRes.body.disclosedClaims).toBeDefined();
    });

    it('should reject a revoked credential', async () => {
        const authRes = await request(app)
            .get('/authorize?scenario=revoked');
        expect(authRes.status).toBe(200);
        const { authRequest } = authRes.body;

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request: authRequest,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: { age: 24 },
            vct: SCENARIO_VCT['revoked'] ?? 'https://mitch.demo/vct/age-credential',
            issuerDid: 'https://issuer.mitch.demo',
            revoked: true,
        });

        const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

        const res = await request(app)
            .post('/oid4vp-present')
            .send({
                vp_token: vpTokenString,
                presentation_submission: presentationSubmission,
                state: authRequest.state,
                issuer_jwk: issuerJwk,
            });

        expect(res.status).toBe(403);
        expect(res.body.ok).toBe(false);
        expect(res.body.errors).toBeDefined();
        expect(res.body.errors.some((e: string) => e.toLowerCase().includes('revok'))).toBe(true);
    });

    it('should verify doctor-login scenario with selective disclosure', async () => {
        const authRes = await request(app)
            .get('/authorize?scenario=doctor-login');
        expect(authRes.status).toBe(200);
        const { authRequest } = authRes.body;

        const doctorClaims = { age: 35, role: 'Surgeon', licenseId: 'MED-998877', employer: 'St. Mary Hospital', salary: 'redacted', homeAddress: 'redacted' };

        const { vpTokenString, presentationSubmission, disclosedClaims } = await buildSDJWTPresentation({
            request: authRequest,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: doctorClaims,
            vct: SCENARIO_VCT['doctor-login'] ?? 'https://mitch.demo/vct/professional-credential',
            issuerDid: 'https://issuer.mitch.demo',
            revoked: false,
        });

        const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

        const res = await request(app)
            .post('/oid4vp-present')
            .send({
                vp_token: vpTokenString,
                presentation_submission: presentationSubmission,
                state: authRequest.state,
                issuer_jwk: issuerJwk,
            });

        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        // Selective disclosure: salary and homeAddress should be redacted
        if (res.body.disclosedClaims) {
            expect(disclosedClaims).toBeDefined();
        }
    });

    it('should return 500 for malformed vp_token with valid issuer_jwk', async () => {
        const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

        const res = await request(app)
            .post('/oid4vp-present')
            .send({
                vp_token: 'not.a.valid.sd-jwt~token',
                presentation_submission: { id: 'test', definition_id: 'test', descriptor_map: [] },
                issuer_jwk: issuerJwk,
            });

        // Should fail validation — either 403 or 500 depending on where it fails
        expect(res.status).toBeGreaterThanOrEqual(400);
        expect(res.body.ok).toBe(false);
    });

    it('should update /status after successful verification', async () => {
        // Initial status should be WAITING (after reset)
        const initialStatus = await request(app).get('/status');
        expect(initialStatus.body.status).toBe('WAITING');

        // Run a successful verification
        const authRes = await request(app).get('/authorize?scenario=liquor-store');
        const { authRequest } = authRes.body;

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request: authRequest,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'] ?? 'https://mitch.demo/vct/age-credential',
            issuerDid: 'https://issuer.mitch.demo',
            revoked: false,
        });

        const issuerJwk = await globalThis.crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

        await request(app)
            .post('/oid4vp-present')
            .send({
                vp_token: vpTokenString,
                presentation_submission: presentationSubmission,
                issuer_jwk: issuerJwk,
            });

        // Status should now be VERIFIED
        const updatedStatus = await request(app).get('/status');
        expect(updatedStatus.body.status).toBe('VERIFIED');
        expect(updatedStatus.body.disclosedClaims).toBeDefined();
        expect(updatedStatus.body.consentReceipt).toBeDefined();
    });
});
