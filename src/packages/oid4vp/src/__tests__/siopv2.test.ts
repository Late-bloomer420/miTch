 
import { describe, it, expect, beforeAll } from 'vitest';
import {
    parseSIOPv2Request,
    createSIOPv2Response,
    validateSIOPv2IDToken,
    computePairwiseSub,
    type SIOPv2AuthorizationRequest,
} from '../siopv2';

let holderPrivateKey: CryptoKey;
let holderPublicKey: CryptoKey;

const HOLDER_DID = 'did:example:holder-alice';
const VERIFIER_CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'test-nonce-siopv2-abc';
const STATE = 'state-xyz-123';

beforeAll(async () => {
    const pair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    holderPrivateKey = pair.privateKey;
    holderPublicKey = pair.publicKey;
});

const VALID_REQUEST: SIOPv2AuthorizationRequest = {
    response_type: 'id_token',
    client_id: VERIFIER_CLIENT_ID,
    redirect_uri: 'https://verifier.example.com/callback',
    nonce: NONCE,
    scope: 'openid',
    state: STATE,
};

// ─── E-03.1: Request Parsing ──────────────────────────────────────────────────

describe('SIOPv2 Request Parsing', () => {
    it('parses a valid SIOPv2 authorization request', () => {
        const result = parseSIOPv2Request(VALID_REQUEST);
        expect(result.ok).toBe(true);
        expect(result.request?.nonce).toBe(NONCE);
        expect(result.request?.client_id).toBe(VERIFIER_CLIENT_ID);
    });

    it('rejects invalid response_type', () => {
        const result = parseSIOPv2Request({
            ...VALID_REQUEST,
            response_type: 'vp_token', // not valid for SIOPv2
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('response_type'))).toBe(true);
    });

    it('rejects missing nonce', () => {
        const { nonce: _nonce, ...withoutNonce } = VALID_REQUEST;
        const result = parseSIOPv2Request(withoutNonce);
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('nonce'))).toBe(true);
    });

    it('rejects missing client_id', () => {
        const { client_id: _cid, ...withoutClientId } = VALID_REQUEST;
        const result = parseSIOPv2Request(withoutClientId);
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('client_id'))).toBe(true);
    });

    it('rejects scope without openid', () => {
        const result = parseSIOPv2Request({ ...VALID_REQUEST, scope: 'profile' });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('scope'))).toBe(true);
    });

    it('accepts combined response_type id_token vp_token', () => {
        const result = parseSIOPv2Request({
            ...VALID_REQUEST,
            response_type: 'id_token vp_token',
            scope: 'openid openid4vp',
        });
        expect(result.ok).toBe(true);
    });
});

// ─── E-03.2: Response Generation ─────────────────────────────────────────────

describe('SIOPv2 Response Generation', () => {
    it('creates a valid id_token for a valid request', async () => {
        const response = await createSIOPv2Response(
            VALID_REQUEST, holderPrivateKey, holderPublicKey, HOLDER_DID
        );
        expect(response.id_token).toMatch(/^eyJ/);
        expect(response.state).toBe(STATE);
    });

    it('id_token contains sub_jwk with holder public key', async () => {
        const response = await createSIOPv2Response(
            VALID_REQUEST, holderPrivateKey, holderPublicKey, HOLDER_DID
        );
        const payloadB64 = response.id_token.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.sub_jwk).toBeDefined();
        expect(payload.sub_jwk.kty).toBe('EC');
        expect(payload.sub_jwk.d).toBeUndefined(); // no private key
    });

    it('id_token iss = holderDID, aud = verifier client_id', async () => {
        const response = await createSIOPv2Response(
            VALID_REQUEST, holderPrivateKey, holderPublicKey, HOLDER_DID
        );
        const payloadB64 = response.id_token.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.iss).toBe(HOLDER_DID);
        expect(payload.aud).toBe(VERIFIER_CLIENT_ID);
        expect(payload.nonce).toBe(NONCE);
    });
});

// ─── E-03.3: ID Token Validation ─────────────────────────────────────────────

describe('SIOPv2 ID Token Validation', () => {
    it('validates a correct id_token', async () => {
        const response = await createSIOPv2Response(
            VALID_REQUEST, holderPrivateKey, holderPublicKey, HOLDER_DID
        );
        const result = await validateSIOPv2IDToken(response.id_token, {
            expectedClientId: VERIFIER_CLIENT_ID,
            expectedNonce: NONCE,
            expectedState: STATE,
        });
        expect(result.ok).toBe(true);
        expect(result.payload?.sub).toBeDefined();
        expect(result.payload?.aud).toBe(VERIFIER_CLIENT_ID);
    });

    it('rejects id_token with wrong nonce', async () => {
        const response = await createSIOPv2Response(
            VALID_REQUEST, holderPrivateKey, holderPublicKey, HOLDER_DID
        );
        const result = await validateSIOPv2IDToken(response.id_token, {
            expectedClientId: VERIFIER_CLIENT_ID,
            expectedNonce: 'wrong-nonce',
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('nonce'))).toBe(true);
    });

    it('rejects id_token addressed to wrong verifier (aud mismatch)', async () => {
        const response = await createSIOPv2Response(
            VALID_REQUEST, holderPrivateKey, holderPublicKey, HOLDER_DID
        );
        const result = await validateSIOPv2IDToken(response.id_token, {
            expectedClientId: 'https://evil-verifier.com',
            expectedNonce: NONCE,
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('aud mismatch'))).toBe(true);
    });
});

// ─── E-03.4: Pairwise Sub Uniqueness ─────────────────────────────────────────

describe('Pairwise Subject Uniqueness', () => {
    it('same holder + same verifier → same sub', async () => {
        const sub1 = await computePairwiseSub('https://verifier.example.com', HOLDER_DID);
        const sub2 = await computePairwiseSub('https://verifier.example.com', HOLDER_DID);
        expect(sub1).toBe(sub2);
    });

    it('same holder + different verifier → different sub (unlinkable)', async () => {
        const sub1 = await computePairwiseSub('https://verifier-a.example.com', HOLDER_DID);
        const sub2 = await computePairwiseSub('https://verifier-b.example.com', HOLDER_DID);
        expect(sub1).not.toBe(sub2);
    });

    it('different holders + same verifier → different sub', async () => {
        const sub1 = await computePairwiseSub(VERIFIER_CLIENT_ID, 'did:example:alice');
        const sub2 = await computePairwiseSub(VERIFIER_CLIENT_ID, 'did:example:bob');
        expect(sub1).not.toBe(sub2);
    });
});
