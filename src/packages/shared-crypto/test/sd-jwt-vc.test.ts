/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, beforeAll } from 'vitest';
import {
    issueSDJWTVC,
    validateSDJWTVC,
    createKeyBindingJWT,
    validateKeyBindingJWT,
    extractCNFPublicKey,
    buildCNFClaim,
    type SDJWTVCPayload,
} from '../src/sd-jwt-vc';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

let issuerPrivateKey: CryptoKey;
let issuerPublicKey: CryptoKey;
let holderPrivateKey: CryptoKey;
let holderPublicKey: CryptoKey;

beforeAll(async () => {
    const issuerPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    issuerPrivateKey = issuerPair.privateKey;
    issuerPublicKey = issuerPair.publicKey;

    const holderPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    holderPrivateKey = holderPair.privateKey;
    holderPublicKey = holderPair.publicKey;
});

const VALID_VCT = 'https://credentials.example.com/identity_credential';
const VALID_ISS = 'https://issuer.example.com';

// ─── E-10.1: Issuance — happy path ───────────────────────────────────────────

describe('SD-JWT VC Issuance', () => {
    it('issues a valid SD-JWT VC with all required claims', async () => {
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            sub: 'did:example:holder',
        }, issuerPrivateKey);

        expect(jwt).toMatch(/^eyJ/); // compact JWT
        // Decode payload
        const parts = jwt.split('.');
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.vct).toBe(VALID_VCT);
        expect(payload.iss).toBe(VALID_ISS);
        expect(payload._sd_alg).toBe('sha-256');
    });

    it('throws if iss is missing', async () => {
        await expect(issueSDJWTVC({
            iss: '',
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
        }, issuerPrivateKey)).rejects.toThrow('iss is required');
    });

    it('throws if vct is not a URI', async () => {
        await expect(issueSDJWTVC({
            iss: VALID_ISS,
            vct: 'not-a-uri',
            iat: Math.floor(Date.now() / 1000),
        }, issuerPrivateKey)).rejects.toThrow('vct must be a URI');
    });

    it('includes cnf claim when holder key provided', async () => {
        const cnf = await buildCNFClaim(holderPublicKey);
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            cnf,
        }, issuerPrivateKey);
        const parts = jwt.split('.');
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.cnf).toBeDefined();
        expect(payload.cnf.jwk).toBeDefined();
        expect(payload.cnf.jwk.kty).toBe('EC');
    });
});

// ─── E-10.2: Validation — happy path ─────────────────────────────────────────

describe('SD-JWT VC Validation', () => {
    it('validates a correctly issued SD-JWT VC', async () => {
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
        }, issuerPrivateKey);

        const result = await validateSDJWTVC(jwt, issuerPublicKey);
        expect(result.ok).toBe(true);
        expect(result.errors).toHaveLength(0);
        expect(result.payload?.vct).toBe(VALID_VCT);
    });

    it('rejects expired credential', async () => {
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000) - 7200,
            exp: Math.floor(Date.now() / 1000) - 3600,
        }, issuerPrivateKey);

        const result = await validateSDJWTVC(jwt, issuerPublicKey);
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('expired'))).toBe(true);
    });

    it('rejects tampered JWT (wrong signature)', async () => {
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
        }, issuerPrivateKey);

        const tampered = jwt.slice(0, -4) + 'XXXX';
        const result = await validateSDJWTVC(tampered, issuerPublicKey);
        expect(result.ok).toBe(false);
        expect(result.errors[0]).toMatch(/Signature verification failed/);
    });

    it('validates status claim structure', async () => {
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            status: {
                status_list: {
                    idx: 42,
                    uri: 'https://issuer.example.com/statuslist/1',
                },
            },
        }, issuerPrivateKey);

        const result = await validateSDJWTVC(jwt, issuerPublicKey);
        expect(result.ok).toBe(true);
        expect(result.payload?.status?.status_list.idx).toBe(42);
    });

    it('rejects invalid status claim', async () => {
        // Manually crafted payload with bad status
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            status: { status_list: { idx: 'bad' as any, uri: 123 as any } },
        }, issuerPrivateKey);

        const result = await validateSDJWTVC(jwt, issuerPublicKey);
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('status_list'))).toBe(true);
    });

    it('validates nbf (not-before) constraint', async () => {
        const jwt = await issueSDJWTVC({
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            nbf: Math.floor(Date.now() / 1000) + 3600, // 1hr in future
        }, issuerPrivateKey);

        const result = await validateSDJWTVC(jwt, issuerPublicKey);
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('not yet valid'))).toBe(true);
    });
});

// ─── E-10.3: Key Binding JWT ──────────────────────────────────────────────────

describe('Key Binding JWT (kb+jwt)', () => {
    const SD_JWT_WITH_DISCLOSURES = 'eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.payload.sig~disclosure1~disclosure2~';
    const AUD = 'https://verifier.example.com';
    const NONCE = 'test-nonce-12345';

    it('creates and validates a key binding JWT', async () => {
        const kbJwt = await createKeyBindingJWT(
            { aud: AUD, nonce: NONCE, sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES },
            holderPrivateKey
        );

        expect(kbJwt).toMatch(/^eyJ/);
        const result = await validateKeyBindingJWT(kbJwt, holderPublicKey, {
            expectedAud: AUD,
            expectedNonce: NONCE,
            sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES,
        });

        expect(result.ok).toBe(true);
        expect(result.payload?.aud).toBe(AUD);
        expect(result.payload?.nonce).toBe(NONCE);
        expect(result.payload?.sd_hash).toBeDefined();
    });

    it('rejects kb+jwt with wrong aud', async () => {
        const kbJwt = await createKeyBindingJWT(
            { aud: AUD, nonce: NONCE, sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES },
            holderPrivateKey
        );
        const result = await validateKeyBindingJWT(kbJwt, holderPublicKey, {
            expectedAud: 'https://evil-verifier.example.com',
            expectedNonce: NONCE,
            sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES,
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('aud mismatch'))).toBe(true);
    });

    it('rejects kb+jwt with wrong nonce', async () => {
        const kbJwt = await createKeyBindingJWT(
            { aud: AUD, nonce: NONCE, sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES },
            holderPrivateKey
        );
        const result = await validateKeyBindingJWT(kbJwt, holderPublicKey, {
            expectedAud: AUD,
            expectedNonce: 'wrong-nonce',
            sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES,
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('nonce mismatch'))).toBe(true);
    });

    it('rejects kb+jwt when SD-JWT hash does not match', async () => {
        const kbJwt = await createKeyBindingJWT(
            { aud: AUD, nonce: NONCE, sdJwtWithDisclosures: SD_JWT_WITH_DISCLOSURES },
            holderPrivateKey
        );
        const result = await validateKeyBindingJWT(kbJwt, holderPublicKey, {
            expectedAud: AUD,
            expectedNonce: NONCE,
            sdJwtWithDisclosures: 'different~jwt~disclosures~', // different SD-JWT
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('sd_hash'))).toBe(true);
    });
});

// ─── E-10.4: CNF Key Extraction ───────────────────────────────────────────────

describe('CNF Key Binding', () => {
    it('extracts public key from cnf claim', async () => {
        const cnf = await buildCNFClaim(holderPublicKey);
        const payload: SDJWTVCPayload = {
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
            cnf,
        };
        const extracted = await extractCNFPublicKey(payload);
        expect(extracted).not.toBeNull();
        expect(extracted?.type).toBe('public');
    });

    it('returns null when no cnf claim', async () => {
        const payload: SDJWTVCPayload = {
            iss: VALID_ISS,
            vct: VALID_VCT,
            iat: Math.floor(Date.now() / 1000),
        };
        const extracted = await extractCNFPublicKey(payload);
        expect(extracted).toBeNull();
    });
});
