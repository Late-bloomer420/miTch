import express, { type Express } from 'express';
import rateLimit from 'express-rate-limit';
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
import { verifyData } from '@askmi/shared-crypto';
import {
    buildOID4VPRequest,
    buildSDJWTPresentation,
    validateSDJWTPresentation,
    buildSessionCleanup,
    SCENARIO_VCT,
    SCENARIO_LABELS,
} from '@mitch/oid4vp';
import { trustListResolver } from '@askmi/shared-crypto';
import { SimpleMetrics } from './metrics.js';
import fs from 'fs';
import path from 'path';

export const app: Express = express();

// Initialize Trust List Resolver
const MITCH_TSL_URL = process.env.MITCH_TSL_URL || 'http://localhost:3005/v1/eudi-lotl.json';
trustListResolver.setUrl(MITCH_TSL_URL);
const ISSUER_BASE_URL = process.env.ISSUER_BASE_URL || 'http://localhost:3005';

const isTestMode = process.env.MITCH_TEST_MODE === '1';
/**
 * G-12: Production-safe trust proxy configuration
 */
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const TRUST_PROXY_HOPS = Number.parseInt(process.env.TRUST_PROXY_HOPS || '1', 10);
const TRUST_PROXY_CIDR = process.env.TRUST_PROXY_CIDR;
if (TRUST_PROXY) {
    if (TRUST_PROXY_CIDR) {
        const cidrs = TRUST_PROXY_CIDR.split(',').map(s => s.trim()).filter(Boolean);
        app.set('trust proxy', cidrs);
    } else {
        app.set('trust proxy', Number.isFinite(TRUST_PROXY_HOPS) ? TRUST_PROXY_HOPS : 1);
    }
}

// Enable CORS so the Wallet PWA and Frontend can talk to us
app.use(cors());
app.use(express.json());

// T-44: Metrics Collection
const metrics = new SimpleMetrics();

// Pilot State (In-memory for PoC)
let lastVerificationStatus: 'WAITING' | 'SCANNED' | 'VERIFIED' | 'FAILED' | 'EXPIRED' = 'WAITING';
let lastRequestTimestamp: number = Date.now();
const REQUEST_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
let lastIssuer: string | null = null;
let lastDisclosedClaims: Record<string, unknown> | null = null;
let lastConsentReceipt: Record<string, unknown> | null = null;

// Scenario credential fixtures (wallet simulation claims)
const SCENARIO_CLAIMS: Record<string, Record<string, unknown>> = {
    'liquor-store':  { age: 24, dateOfBirth: '2000-01-01', name: 'Max Mustermann', address: 'Zirl, AT', nationalId: 'AT-123456' },
    'doctor-login':  { age: 35, role: 'Surgeon', licenseId: 'MED-998877', employer: 'St. Mary Hospital', salary: 'redacted', homeAddress: 'redacted' },
    'ehds-er':       { bloodGroup: 'A+', allergies: 'Penicillin, Cashew nuts', emergencyContacts: 'Mother: +49-151-555-0100', activeProblems: 'Asthma', diagnosis: '[full history]', geneticData: '[genetic profile]', insuranceId: 'INS-redacted' },
    'pharmacy':      { medication: 'Amoxicillin 500mg', dosageInstruction: '1 tablet every 8 hours', refillsRemaining: 2, diagnosis: '[prescribing diagnosis]', insuranceId: 'INS-redacted', geneticData: '[genetic markers]' },
    'revoked':       { age: 24 },
};

const KEY_FILE = path.join(process.cwd(), 'verifier-key.json');
const NONCE_STORE_FILE = path.join(process.cwd(), 'nonce-cache.json');

const nonceStore = new NonceStore({
    ttlMs: 10 * 60 * 1000,
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

const presentRouteLimiter = rateLimit({
    windowMs: 60_000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
});

/**
 * PoC Key Resolution Hub
 */
let verifierKeyPair: CryptoKeyPair | null = null;

async function getVerifierKeys(): Promise<CryptoKeyPair> {
    if (verifierKeyPair) return verifierKeyPair;
    if (isTestMode) {
        verifierKeyPair = { publicKey: {} as CryptoKey, privateKey: {} as CryptoKey };
        return verifierKeyPair;
    }
    if (fs.existsSync(KEY_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(KEY_FILE, 'utf-8'));
            const publicKey = await globalThis.crypto.subtle.importKey('jwk', data.publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt', 'wrapKey']);
            const privateKey = await globalThis.crypto.subtle.importKey('jwk', data.privateKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt', 'unwrapKey']);
            verifierKeyPair = { publicKey, privateKey };
            return verifierKeyPair;
        } catch (e) { console.warn('Failed to load keys', e); }
    }
    verifierKeyPair = await globalThis.crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey']);
    const pubJwk = await globalThis.crypto.subtle.exportKey('jwk', verifierKeyPair.publicKey);
    const privJwk = await globalThis.crypto.subtle.exportKey('jwk', verifierKeyPair.privateKey);
    fs.writeFileSync(KEY_FILE, JSON.stringify({ publicKey: pubJwk, privateKey: privJwk }, null, 2));
    return verifierKeyPair;
}

// 1. Get current status (for the frontend polling)
app.get('/status', (req, res) => {
    if (lastVerificationStatus === 'WAITING' || lastVerificationStatus === 'SCANNED') {
        if (Date.now() - lastRequestTimestamp > REQUEST_TIMEOUT_MS) {
            lastVerificationStatus = 'EXPIRED';
        }
    }
    res.json({
        status: lastVerificationStatus,
        issuer: lastIssuer,
        verifierDid: 'did:mitch:verifier-liquor-store',
        disclosedClaims: lastDisclosedClaims,
        consentReceipt: lastConsentReceipt,
    });
});

// 1b. Notify that QR was scanned (called by wallet)
app.post('/notify-scan', (req, res) => {
    if (lastVerificationStatus === 'WAITING') {
        lastVerificationStatus = 'SCANNED';
        console.log('[Verifier] 📱 QR Code scanned by wallet');
    }
    res.json({ ok: true });
});

app.get('/', (req, res) => {
    res.type('text/plain').send('miTch Verifier Backend OK.');
});

// ─── W-01: Generate OID4VP Authorization Request ─────────────────────────────
app.get('/authorize', (req, res) => {
    const scenarioId = (req.query['scenario'] as string) || 'liquor-store';
    const baseUrl = process.env['VERIFIER_BASE_URL'] || `${req.protocol}://${req.get('host')}`;
    try {
        const { request, nonce } = buildOID4VPRequest({
            verifierClientId: 'did:mitch:verifier-liquor-store',
            redirectUri: `${baseUrl}/oid4vp-present`,
            scenarioId,
            clientName: SCENARIO_LABELS[scenarioId] ?? scenarioId,
        });
        nonceStore.add(nonce);
        res.json({ authRequest: request, nonce, scenarioId });
    } catch (e: unknown) {
        res.status(400).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
});

// ─── W-02/W-03/W-04/W-05: Wallet-simulated Presentation Flow ─────────────────
app.post('/wallet-present', async (req, res) => {
    const scenarioId: string = (req.body as { scenarioId?: string }).scenarioId ?? 'liquor-store';
    try {
        const baseUrl = process.env['VERIFIER_BASE_URL'] || `${req.protocol}://${req.get('host')}`;
        const { request } = buildOID4VPRequest({ verifierClientId: 'did:mitch:verifier-liquor-store', redirectUri: `${baseUrl}/present`, scenarioId, clientName: SCENARIO_LABELS[scenarioId] ?? scenarioId });
        const issuerKeys = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const holderKeys = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const claims = SCENARIO_CLAIMS[scenarioId] ?? SCENARIO_CLAIMS['liquor-store'];
        const { vpTokenString, presentationSubmission, disclosedClaims } = await buildSDJWTPresentation({ request, issuerPrivateKey: issuerKeys.privateKey, holderKeyPair: holderKeys, claims, vct: SCENARIO_VCT[scenarioId] ?? 'https://mitch.demo/vct/age-credential', issuerDid: 'https://issuer.mitch.demo', revoked: scenarioId === 'revoked', statusListUri: `${ISSUER_BASE_URL}/status-list/1` });
        const validation = await validateSDJWTPresentation({ vpTokenString, presentationSubmission, request, issuerPublicKey: issuerKeys.publicKey, checkRevocation: true, checkTrust: true });
        const { consentReceipt } = buildSessionCleanup({ request, disclosedClaims: validation.disclosedClaims ?? disclosedClaims, outcome: validation.ok ? 'SUCCESS' : 'DENIED' });
        if (validation.ok) {
            lastVerificationStatus = 'VERIFIED';
            lastIssuer = 'https://issuer.mitch.demo';
            lastDisclosedClaims = validation.disclosedClaims ?? null;
            lastConsentReceipt = consentReceipt as unknown as Record<string, unknown>;
            return res.json({ ok: true, disclosedClaims: validation.disclosedClaims, consentReceipt });
        } else {
            lastVerificationStatus = 'FAILED';
            return res.status(403).json({ ok: false, errors: validation.errors });
        }
    } catch (e: unknown) {
        lastVerificationStatus = 'FAILED';
        return res.status(500).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
});

// ─── B-02: OID4VP Direct Post Endpoint (Wallet → Verifier) ──────────────────
app.post('/oid4vp-present', async (req, res) => {
    try {
        const body = req.body as { vp_token?: string; presentation_submission?: unknown; state?: string; issuer_jwk?: JsonWebKey };
        if (!body.vp_token) return res.status(400).json({ ok: false, error: 'Missing vp_token' });
        if (!body.presentation_submission) return res.status(400).json({ ok: false, error: 'Missing presentation_submission' });
        if (!body.issuer_jwk) return res.status(400).json({ ok: false, error: 'Missing issuer_jwk' });
        const issuerPublicKey = await globalThis.crypto.subtle.importKey('jwk', body.issuer_jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        const baseUrl = process.env['VERIFIER_BASE_URL'] || `${req.protocol}://${req.get('host')}`;
        const reconstructedRequest = { response_type: 'vp_token' as const, client_id: 'did:mitch:verifier-liquor-store', redirect_uri: `${baseUrl}/oid4vp-present`, nonce: '', presentation_definition: { id: 'reconstructed', input_descriptors: [] }, response_mode: 'direct_post' as const, state: body.state };
        const vpParts = body.vp_token.split('~');
        const kbJwtPart = vpParts[vpParts.length - 1];
        if (kbJwtPart) {
            try {
                const kbPayloadB64 = kbJwtPart.split('.')[1];
                const kbPayload = JSON.parse(atob(kbPayloadB64.replace(/-/g, '+').replace(/_/g, '/')));
                reconstructedRequest.nonce = kbPayload.nonce ?? '';
            } catch {}
        }
        const validation = await validateSDJWTPresentation({ vpTokenString: body.vp_token, presentationSubmission: body.presentation_submission as any, request: reconstructedRequest, issuerPublicKey, checkRevocation: true, checkTrust: true });
        const { consentReceipt } = buildSessionCleanup({ request: reconstructedRequest, disclosedClaims: validation.disclosedClaims ?? {}, outcome: validation.ok ? 'SUCCESS' : 'DENIED' });
        if (validation.ok) {
            lastVerificationStatus = 'VERIFIED';
            lastIssuer = 'https://issuer.mitch.demo';
            lastDisclosedClaims = validation.disclosedClaims ?? null;
            lastConsentReceipt = consentReceipt as unknown as Record<string, unknown>;
            return res.json({ ok: true, disclosedClaims: validation.disclosedClaims, consentReceipt });
        } else {
            lastVerificationStatus = 'FAILED';
            return res.status(403).json({ ok: false, errors: validation.errors });
        }
    } catch (e: unknown) {
        lastVerificationStatus = 'FAILED';
        return res.status(500).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), metrics: metrics.get() });
});

app.get(['/did.json', '/.well-known/did.json'], async (req, res) => {
    const keys = await getVerifierKeys();
    const publicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', keys.publicKey);
    const baseUrl = process.env.VERIFIER_BASE_URL || `${req.protocol}://${req.get('host')}`;
    res.json({ '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'], id: 'did:mitch:verifier-liquor-store', verificationMethod: [{ id: 'did:mitch:verifier-liquor-store#key-1', type: 'JsonWebKey2020', controller: 'did:mitch:verifier-liquor-store', publicKeyJwk }], service: [{ id: 'did:mitch:verifier-liquor-store#present', type: 'VerifierService', serviceEndpoint: `${baseUrl}/present` }] });
});

app.post('/present', presentRouteLimiter, async (req, res) => {
    try {
        const requesterId = getRequesterId(req);
        const rate = rateLimiter.check(requesterId, Date.now());
        if (!rate.allowed) {
            const resetAfterSeconds = Math.ceil(rate.resetInMs / 1000);
            res.setHeader('Retry-After', String(resetAfterSeconds));
            res.setHeader('X-RateLimit-Reset-After', String(resetAfterSeconds));
            res.setHeader('X-RateLimit-Reset', String(Math.ceil((Date.now() + rate.resetInMs) / 1000)));
            return res.status(429).json({ ok: false, error: 'RATE_LIMIT_EXCEEDED' });
        }
        const keys = await getVerifierKeys();
        const sdk = new VerifierSDK({ privateKey: keys.privateKey, verifierDid: 'did:mitch:verifier-liquor-store' });
        const result = await sdk.verifyPresentation<Record<string, unknown>>(JSON.stringify(req.body));
        const presentation = result.vp;
        const firstPres = (presentation as any).presentations?.[0];
        const agePredicateId = 'age >= 18';
        const zkpProof = (firstPres?.zkp_proofs)?.[agePredicateId];
        let isVerified = false;
        if (zkpProof) {
            const expectedRequest: PredicateRequest = { verifierDid: 'did:mitch:verifier-liquor-store', nonce: zkpProof.proof.binding.nonce, purpose: 'Age Verification', timestamp: zkpProof.proof.evaluatedAt, predicates: [CommonPredicates.ageAtLeast(18)] };
            const allowedHashes = await buildAllowedPredicateSet(expectedRequest.predicates as Predicate[]);
            const verifyFn = async (data: string, sig: string) => {
                const key = await globalThis.crypto.subtle.importKey('jwk', zkpProof.publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
                return await verifyData(data, sig, key);
            };
            const verification = await verifyPredicateResult(zkpProof, expectedRequest, allowedHashes, verifyFn);
            if (verification.valid && zkpProof.proof.allPassed) isVerified = true;
        }
        if (isVerified) {
            lastVerificationStatus = 'VERIFIED';
            const issuerRef = (presentation as any).metadata?.issuer_trust_refs?.[0];
            lastIssuer = (typeof issuerRef === 'string' ? issuerRef : issuerRef?.issuer) || 'Unknown Trusted Issuer';
            res.json({ ok: true, message: `Welcome! Verified via ${lastIssuer}` });
        } else {
            lastVerificationStatus = 'FAILED';
            res.status(403).json({ ok: false, error: 'AGE_NOT_VERIFIED' });
        }
    } catch (e: unknown) {
        console.warn(
            '[Verifier] /present verification failed:',
            e instanceof Error ? `${e.name}: ${e.message}` : String(e)
        );
        lastVerificationStatus = 'FAILED';
        res.status(400).json({ ok: false, error: 'VERIFICATION_FAILED' });
    }
});

app.post('/reset', (req, res) => {
    lastVerificationStatus = 'WAITING';
    lastRequestTimestamp = Date.now();
    lastIssuer = null;
    lastDisclosedClaims = null;
    lastConsentReceipt = null;
    nonceStore.clear();
    res.json({ ok: true });
});

export default app;
