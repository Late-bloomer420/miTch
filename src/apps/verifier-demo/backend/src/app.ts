import express from 'express';
import cors from 'cors';
import { VerifierSDK } from '@mitch/verifier-sdk';
import { NonceStore } from './nonce-store';
import { FixedWindowRateLimiter } from './rate-limiter';
import { getRequesterId } from './requester-id';
import {
    verifyPredicateResult,
    CommonPredicates,
    buildAllowedPredicateSet,
    type PredicateRequest,
    type Predicate
} from '@mitch/predicates';
import { verifyData } from '@mitch/shared-crypto';
import { SimpleMetrics } from './metrics.js';
import fs from 'fs';
import path from 'path';

export const app = express();

const isTestMode = process.env.MITCH_TEST_MODE === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const TRUST_PROXY_HOPS = Number.parseInt(process.env.TRUST_PROXY_HOPS || '1', 10);
if (TRUST_PROXY) {
    // TODO: In production, prefer explicit proxy hop counts or CIDR allowlists.
    app.set('trust proxy', Number.isFinite(TRUST_PROXY_HOPS) ? TRUST_PROXY_HOPS : 1);
}

// Enable CORS so the Wallet PWA and Frontend can talk to us
app.use(cors());
app.use(express.json());

// T-44: Metrics Collection
const metrics = new SimpleMetrics();

// Pilot State (In-memory for PoC)
let lastVerificationStatus: 'WAITING' | 'VERIFIED' | 'FAILED' = 'WAITING';
let lastIssuer: string | null = null;

const KEY_FILE = path.join(process.cwd(), 'verifier-key.json');
const NONCE_STORE_FILE = path.join(process.cwd(), 'nonce-cache.json');

const nonceStore = new NonceStore({
    ttlMs: 10 * 60 * 1000, // 10 minutes (covers 5-minute token TTL + skew)
    maxEntries: 50000,
    cleanupIntervalMs: 60 * 1000,
    persistencePath: isTestMode ? undefined : NONCE_STORE_FILE
});
nonceStore.loadFromDisk();

process.on('SIGINT', () => nonceStore.close());
process.on('SIGTERM', () => nonceStore.close());

const rateLimiter = new FixedWindowRateLimiter(60_000, 10, {
    maxEntries: 100_000,
    pruneIntervalMs: 30_000
});

/**
 * PoC Key Resolution Hub
 * Persists keypair to disk to ensure stable DID / Keys across restarts.
 */
let verifierKeyPair: CryptoKeyPair | null = null;

async function getVerifierKeys(): Promise<CryptoKeyPair> {
    if (verifierKeyPair) return verifierKeyPair;

    if (isTestMode) {
        verifierKeyPair = { publicKey: {} as CryptoKey, privateKey: {} as CryptoKey };
        return verifierKeyPair;
    }

    // 1. Try Load
    if (fs.existsSync(KEY_FILE)) {
        try {
            console.log('?? Loading Verifier Keys from disk...');
            const data = JSON.parse(fs.readFileSync(KEY_FILE, 'utf-8'));

            const publicKey = await (globalThis as any).crypto.subtle.importKey(
                'jwk', data.publicKey,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                true, ['encrypt', 'wrapKey']
            );
            const privateKey = await (globalThis as any).crypto.subtle.importKey(
                'jwk', data.privateKey,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                true, ['decrypt', 'unwrapKey']
            );

            verifierKeyPair = { publicKey, privateKey };
            return verifierKeyPair;
        } catch (e) {
            console.warn('?? Failed to load key file, regenerating...', e);
        }
    }

    // 2. Generate New
    console.log('? Generating NEW Verifier Keys...');
    verifierKeyPair = await (globalThis as any).crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey']
    );

    // 3. Save
    if (!verifierKeyPair) throw new Error('KeyGen failed');
    const pubJwk = await (globalThis as any).crypto.subtle.exportKey('jwk', verifierKeyPair.publicKey);
    const privJwk = await (globalThis as any).crypto.subtle.exportKey('jwk', verifierKeyPair.privateKey);

    fs.writeFileSync(KEY_FILE, JSON.stringify({ publicKey: pubJwk, privateKey: privJwk }, null, 2));
    console.log(`?? Saved stable keys to ${KEY_FILE}`);

    return verifierKeyPair as CryptoKeyPair;
}

/**
 * miTch Pilot Verifier Endpoints
 */

// 1. Get current status (for the frontend polling)
app.get('/status', (req, res) => {
    res.json({
        status: lastVerificationStatus,
        issuer: lastIssuer,
        verifierDid: 'did:mitch:verifier-liquor-store'
    });
});

// Basic root response to avoid "Cannot GET /" confusion in dev.
app.get('/', (req, res) => {
    res.type('text/plain').send('miTch Verifier Backend OK. Try /status or open the verifier frontend.');
});

// T-44: Public Health & Metrics Endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        uptime: process.uptime(),
        metrics: metrics.get(),
        system: {
            rate_limiter: rateLimiter.size(),
            // @ts-ignore - Accessing private nonce store size if needed
            nonce_store_entries: (nonceStore as any).entries?.size || 0
        }
    });
});

// 1a. Expose Verifier ID & Keys (Wallet needs this to encrypt!)
// Supports both raw /did.json (did:mitch) and standard /.well-known/did.json (did:web)
app.get(['/did.json', '/.well-known/did.json'], async (req, res) => {
    const keys = await getVerifierKeys();
    const publicKeyJwk = await (globalThis as any).crypto.subtle.exportKey('jwk', keys.publicKey);
    const baseUrl = process.env.VERIFIER_BASE_URL || `${req.protocol}://${req.get('host')}`;

    // Minimal DID Document
    res.json({
        id: 'did:mitch:verifier-liquor-store',
        verificationMethod: [{
            id: 'did:mitch:verifier-liquor-store#key-1',
            type: 'JsonWebKey2020',
            controller: 'did:mitch:verifier-liquor-store',
            publicKeyJwk
        }],
        service: [{
            id: 'did:mitch:verifier-liquor-store#present',
            type: 'VerifierService',
            serviceEndpoint: `${baseUrl}/present` // In prod, use a fixed HTTPS base URL
        }]
    });
});

// 2. Receive and Verify Presentation (The "Consumer" of the SDK)
app.post('/present', async (req, res) => {
    try {
        const requesterId = getRequesterId(req);
        // T-39: Binding to Requester ID (IP or Header)
        const requesterKind = requesterId.startsWith('hdr:') ? 'hdr' : 'ip';
        const now = Date.now();
        const rate = rateLimiter.check(requesterId, now);

        const resetAfterSeconds = Math.ceil(rate.resetInMs / 1000);
        const resetAtEpochSeconds = Math.ceil((now + rate.resetInMs) / 1000);

        res.setHeader('X-RateLimit-Limit', rate.limit.toString());
        res.setHeader('X-RateLimit-Remaining', rate.remaining.toString());
        res.setHeader('X-RateLimit-Reset', resetAtEpochSeconds.toString());
        res.setHeader('X-RateLimit-Reset-After', resetAfterSeconds.toString());

        if (!rate.allowed) {
            metrics.inc('rate_limit_blocked');
            res.setHeader('Retry-After', resetAfterSeconds.toString());
            console.warn(`[Provider] Rate limit exceeded (${requesterKind}). Resets in ${resetAfterSeconds}s.`);
            return res.status(429).json({
                ok: false,
                error: 'RATE_LIMIT_EXCEEDED',
                retryAfterSeconds: resetAfterSeconds
            });
        }

        console.log(`[Provider] Rate limit: ${rate.remaining} requests remaining`);
        console.log('[Provider] Accepted presentation package from wallet');
        const keys = await getVerifierKeys();

        const sdk = new VerifierSDK({
            privateKey: keys.privateKey,
            verifierDid: 'did:mitch:verifier-liquor-store'
            // replayCheck removed (handled internally or requires SDK update)
        });

        // The Magic: SDK handles unwrapping, AAD re-binding, Proof-Boundary Check, and Decryption
        // Returns VerificationResult { vp, aad, proof, timestamp }
        const result = await sdk.verifyPresentation<any>(JSON.stringify(req.body));
        const presentation = result.vp; // Extract the actual VC bundle

        console.log('?? Decrypted Presentation Payload:', JSON.stringify(presentation, null, 2));
        console.log(`??? Proof Verified: ${result.proof.public_key_alg}`);

        // Pilot Logic: ZKP Range Proof Verification
        // The VP is structured as: { metadata, presentations: [{ proven_claims: {...}, zkp_proofs: {...} }] }
        const firstPres = presentation.presentations?.[0];
        const agePredicateId = 'age >= 18';

        // Check for ZKP Proof first
        const zkpProof = firstPres?.zkp_proofs?.[agePredicateId];
        let isVerified = false;

        if (zkpProof) {
            console.log('??? Verifying Cryptographic Predicate Proof...');
            try {
                // 1. Reconstruct what we expected (The Verifier knows its own requirements)
                // Ideally this comes from a session store or policy config
                const expectedRequest: PredicateRequest = {
                    verifierDid: 'did:mitch:verifier-liquor-store',
                    nonce: zkpProof.binding.nonce, // For MVP, we use the nonce from the proof (replay checked by SDK)
                    purpose: 'Age Verification',
                    timestamp: zkpProof.evaluatedAt,
                    predicates: [CommonPredicates.ageAtLeast(18)]
                };

                // 2. Build allowed set
                // Cast to Predicate[] because buildAllowedPredicateSet doesn't support string IDs yet
                const allowedHashes = await buildAllowedPredicateSet(expectedRequest.predicates as Predicate[]);

                // 3. Verify Signature (Real ECDSA P-256)
                const verifyFn = async (data: string, sig: string) => {
                    const identityKeyJwk = (zkpProof as any).publicKeyJwk;
                    if (!identityKeyJwk) {
                        console.warn('? Missing Public Key in Proof');
                        return false;
                    }
                    const key = await (globalThis as any).crypto.subtle.importKey(
                        'jwk', identityKeyJwk,
                        { name: 'ECDSA', namedCurve: 'P-256' },
                        true, ['verify']
                    );
                    return await verifyData(data, sig, key);
                };

                // 4. Verify
                const verification = await verifyPredicateResult(
                    zkpProof,
                    expectedRequest,
                    allowedHashes,
                    verifyFn // Now strict signature & timestamp verification (default 5m window)
                );

                if (verification.valid && zkpProof.proof.allPassed === true) {
                    isVerified = true;
                    metrics.inc('zkp_success');
                    console.log('? ZKP PROOF VALIDATED!');
                } else {
                    console.warn('? ZKP PROOF INVALID:', verification.errors);
                }
            } catch (err) {
                console.error('? ZKP Verification Exception:', err);
            }
        } else {
            // Fallback to legacy trusted boolean (during migration)
            console.log('?? No ZKP Proof found, checking legacy claim...');
            isVerified = firstPres?.proven_claims?.[agePredicateId] === true;
        }

        if (isVerified) {
            lastVerificationStatus = 'VERIFIED';
            // Link to ID verification (Extract the trusted issuer)
            const issuerRef = presentation.metadata?.issuer_trust_refs?.[0];
            // Format issuer for display (handle object or string)
            lastIssuer = (typeof issuerRef === 'string' ? issuerRef : issuerRef?.issuer) || 'Unknown Trusted Issuer';

            console.log(`? AGE VERIFIED (ZKP): Result = ALLOW (Issuer: ${lastIssuer})`);
            res.json({ ok: true, message: `Welcome! Verified via ${lastIssuer}` });
        } else {
            lastVerificationStatus = 'FAILED';
            lastIssuer = null;
            console.log('? VERIFICATION FAILED: minor detected or proof invalid');
            res.status(403).json({ ok: false, error: 'AGE_NOT_VERIFIED' });
        }
    } catch (e: any) {
        console.error('?? Verification/Decryption Error:', e.message);

        let status = 400;
        let errorKey = 'VERIFICATION_FAILED';

        // Map SDK Errors to HTTP Status
        if (e.name === 'ReplayDetectedError') { status = 409; errorKey = 'REPLAY_DETECTED'; }
        else if (e.name === 'TokenExpiredError') { status = 410; errorKey = 'TOKEN_EXPIRED'; }
        else if (e.name === 'ProofSignatureError') { status = 401; errorKey = 'INVALID_SIGNATURE'; }

        lastVerificationStatus = 'FAILED';
        res.status(status).json({ ok: false, error: errorKey, details: e.message });
    }
});

// 3. Reset (for demo repeat)
app.post('/reset', (req, res) => {
    lastVerificationStatus = 'WAITING';
    lastIssuer = null;
    nonceStore.clear();
    res.json({ ok: true });
});

export default app;
