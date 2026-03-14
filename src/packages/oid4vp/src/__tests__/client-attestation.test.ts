 
import { describe, it, expect, beforeAll } from 'vitest';
import {
    issueClientAttestation,
    createClientAttestationPoP,
    validateClientAttestationChain,
} from '../client-attestation';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

let providerPrivateKey: CryptoKey;
let providerPublicKey: CryptoKey;
let walletPrivateKey: CryptoKey;
let walletPublicKey: CryptoKey;

const PROVIDER_ISS = 'https://wallet-provider.example.com';
const CLIENT_ID = 'https://my-wallet.example.com';
const VERIFIER_AUD = 'https://verifier.example.com/authorize';

beforeAll(async () => {
    const provPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    providerPrivateKey = provPair.privateKey;
    providerPublicKey = provPair.publicKey;

    const walletPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    walletPrivateKey = walletPair.privateKey;
    walletPublicKey = walletPair.publicKey;
});

async function buildValidChain(overrides?: {
    nonce?: string;
    audience?: string;
}) {
    const attestation = await issueClientAttestation({
        iss: PROVIDER_ISS,
        clientId: CLIENT_ID,
        walletPublicKey,
        walletName: 'miTch Wallet',
    }, providerPrivateKey);

    const pop = await createClientAttestationPoP({
        clientId: CLIENT_ID,
        audience: overrides?.audience ?? VERIFIER_AUD,
        nonce: overrides?.nonce,
    }, walletPrivateKey);

    return { clientAttestation: attestation, clientAttestationPoP: pop };
}

// ─── E-04.1: Attestation Issuance ────────────────────────────────────────────

describe('Client Attestation Issuance', () => {
    it('issues a client attestation JWT with cnf.jwk', async () => {
        const jwt = await issueClientAttestation({
            iss: PROVIDER_ISS,
            clientId: CLIENT_ID,
            walletPublicKey,
        }, providerPrivateKey);

        expect(jwt).toMatch(/^eyJ/);
        const payloadB64 = jwt.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.iss).toBe(PROVIDER_ISS);
        expect(payload.sub).toBe(CLIENT_ID);
        expect(payload.cnf).toBeDefined();
        expect(payload.cnf.jwk.kty).toBe('EC');
        expect(payload.cnf.jwk.d).toBeUndefined(); // no private key
    });

    it('includes wallet_name when provided', async () => {
        const jwt = await issueClientAttestation({
            iss: PROVIDER_ISS,
            clientId: CLIENT_ID,
            walletPublicKey,
            walletName: 'miTch Wallet v1',
        }, providerPrivateKey);
        const payloadB64 = jwt.split('.')[1];
        const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.wallet_name).toBe('miTch Wallet v1');
    });
});

// ─── E-04.2: PoP JWT Creation ─────────────────────────────────────────────────

describe('Client Attestation PoP Creation', () => {
    it('creates a PoP JWT with unique jti', async () => {
        const pop1 = await createClientAttestationPoP({
            clientId: CLIENT_ID, audience: VERIFIER_AUD,
        }, walletPrivateKey);
        const pop2 = await createClientAttestationPoP({
            clientId: CLIENT_ID, audience: VERIFIER_AUD,
        }, walletPrivateKey);

        const jti1 = JSON.parse(atob(pop1.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).jti;
        const jti2 = JSON.parse(atob(pop2.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).jti;
        expect(jti1).not.toBe(jti2);
    });

    it('includes nonce in PoP when provided', async () => {
        const pop = await createClientAttestationPoP({
            clientId: CLIENT_ID, audience: VERIFIER_AUD, nonce: 'verifier-nonce-42',
        }, walletPrivateKey);
        const payload = JSON.parse(atob(pop.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        expect(payload.nonce).toBe('verifier-nonce-42');
    });
});

// ─── E-04.3: Chain Validation ─────────────────────────────────────────────────

describe('Client Attestation Chain Validation', () => {
    it('validates a correct attestation chain', async () => {
        const chain = await buildValidChain();
        const result = await validateClientAttestationChain(chain, {
            expectedAudience: VERIFIER_AUD,
            providerPublicKey,
        });
        expect(result.ok).toBe(true);
        expect(result.clientId).toBe(CLIENT_ID);
        expect(result.walletPublicKey).toBeDefined();
    });

    it('validates chain with nonce binding', async () => {
        const chain = await buildValidChain({ nonce: 'required-nonce' });
        const result = await validateClientAttestationChain(chain, {
            expectedAudience: VERIFIER_AUD,
            expectedNonce: 'required-nonce',
            providerPublicKey,
        });
        expect(result.ok).toBe(true);
    });

    it('rejects wrong audience in PoP', async () => {
        const chain = await buildValidChain({ audience: 'https://evil-verifier.com' });
        const result = await validateClientAttestationChain(chain, {
            expectedAudience: VERIFIER_AUD,
            providerPublicKey,
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('aud mismatch'))).toBe(true);
    });

    it('detects replay via jti tracking', async () => {
        const chain = await buildValidChain();
        const seenJtis = new Set<string>();

        const r1 = await validateClientAttestationChain(chain, {
            expectedAudience: VERIFIER_AUD,
            providerPublicKey,
            seenJtis,
        });
        expect(r1.ok).toBe(true);

        const r2 = await validateClientAttestationChain(chain, {
            expectedAudience: VERIFIER_AUD,
            providerPublicKey,
            seenJtis,
        });
        expect(r2.ok).toBe(false);
        expect(r2.errors.some(e => e.includes('Replay detected'))).toBe(true);
    });

    it('rejects attestation signed by unknown provider', async () => {
        const unknownPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
        );
        const attestation = await issueClientAttestation({
            iss: PROVIDER_ISS, clientId: CLIENT_ID, walletPublicKey,
        }, unknownPair.privateKey); // wrong key

        const pop = await createClientAttestationPoP({
            clientId: CLIENT_ID, audience: VERIFIER_AUD,
        }, walletPrivateKey);

        const result = await validateClientAttestationChain(
            { clientAttestation: attestation, clientAttestationPoP: pop },
            { expectedAudience: VERIFIER_AUD, providerPublicKey }
        );
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('Client Attestation verification failed'))).toBe(true);
    });

    it('rejects PoP with missing nonce when nonce required', async () => {
        const chain = await buildValidChain(); // no nonce
        const result = await validateClientAttestationChain(chain, {
            expectedAudience: VERIFIER_AUD,
            expectedNonce: 'required-nonce',
            providerPublicKey,
        });
        expect(result.ok).toBe(false);
        expect(result.errors.some(e => e.includes('nonce'))).toBe(true);
    });
});
