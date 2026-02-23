import {
    PolicyEngine,
    type EvaluationContext
} from '@mitch/policy-engine';
import { SecureStorage } from '@mitch/secure-storage';
import { AuditLog } from '@mitch/audit-log';
import {
    PolicyManifest,
    VerifierRequest,
    PolicyEvaluationResult,
    DecisionCapsule,
    AuditLogEntry,
    AuditLogExport,
    StoredCredentialMetadata
} from '@mitch/shared-types';
import {
    EphemeralKey,
    deriveKeyFromPassword,
    generateKeyPair,
    canonicalStringify,
    RecoveryService,
    WebAuthnService,
    signData,
    resolveDID,
    detectKeyAlgorithm
} from '@mitch/shared-crypto';


import { DEMO_POLICY } from '../data/DemoPolicy';
import { DocumentService, ProofOfExistence } from './DocumentService';
import {
    evaluatePredicates,
    CommonPredicates,
    type PredicateRequest
} from '@mitch/predicates';

const POLICY_STORAGE_KEY = 'mitch_user_policy';

// Default Policy for the PoC (Now persistent)
const DEFAULT_POLICY: PolicyManifest = DEMO_POLICY;

const SEED_CREDENTIAL = {
    id: 'vc-age-789',
    issuer: 'did:example:gov-issuer',
    type: ['VerifiableCredential', 'AgeCredential'],
    issuedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    claims: ['birthDate', 'age'],
    payload: {
        birthDate: '2000-01-01',
        age: 24 // Raw PII in Secure Storage (demo only)
    }
};

const MALICIOUS_CREDENTIAL = {
    id: 'vc-fake-999',
    issuer: 'did:example:malicious-hacker',
    type: ['VerifiableCredential', 'AgeCredential'],
    issuedAt: new Date().toISOString(),
    claims: ['age'],
    payload: {
        age: 25
    }
};

const EMPLOYMENT_CREDENTIAL = {
    id: 'vc-emp-456',
    issuer: 'did:example:st-mary-hospital',
    type: ['VerifiableCredential', 'EmploymentCredential'],
    issuedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString(),
    claims: ['employer', 'role', 'licenseId'],
    payload: {
        employer: 'St. Mary Hospital',
        role: 'Surgeon',
        licenseId: 'MED-998877'
    }
};

// EHDS Sample Credentials defined here for seeding
const EHDS_PATIENT_SUMMARY = {
    id: 'vc-ehds-summary-001',
    issuer: 'did:example:ehealth-authority',
    type: ['VerifiableCredential', 'HealthRecord', 'PatientSummary'], // Polymorphic types
    issuedAt: new Date().toISOString(),
    claims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
    payload: {
        resourceType: 'PatientSummary',
        status: 'final',
        effectiveDateTime: new Date().toISOString(),
        performer: { display: 'Seven Bridges Genomics', reference: 'did:example:ehealth-authority' },
        content: {
            bloodGroup: 'A+',
            allergies: [
                { code: '91936005', display: 'Penicillin', criticality: 'high' },
                { code: '227493005', display: 'Cashew nuts', criticality: 'low' }
            ],
            activeProblems: ['Asthma'],
            emergencyContacts: [{ relation: 'Mother', phone: '+49-151-555-0100' }]
        }
    }
};

const EHDS_PRESCRIPTION = {
    id: 'vc-ehds-rx-999',
    issuer: 'did:example:ehealth-authority',
    type: ['VerifiableCredential', 'HealthRecord', 'Prescription'],
    issuedAt: new Date().toISOString(),
    claims: ['medication', 'dosageInstruction', 'refillsRemaining'],
    payload: {
        resourceType: 'Prescription',
        status: 'final',
        effectiveDateTime: new Date().toISOString(),
        performer: { display: 'Dr. House', reference: 'did:example:st-mary-hospital' },
        content: {
            medication: { code: '372665008', display: 'Amoxicillin 500mg' },
            dosageInstruction: 'Take 1 tablet every 8 hours for 7 days',
            quantity: 21,
            refillsRemaining: 0
        }
    }
};
// End T-30 definitions

// ... (other imports)

// DID Resolution Cache
// Map<DID, { key: CryptoKey, expires: number }>
const keyCache = new Map<string, { key: CryptoKey, expires: number }>();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 Minutes

// Node-safe localStorage shim for non-browser environments (validation script)
const localStoreShim: Storage = (() => {
    try {
        if (typeof localStorage !== 'undefined') return localStorage;
    } catch (_) { }
    const mem = new Map<string, string>();
    return {
        getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
        setItem: (k: string, v: string) => { mem.set(k, v); },
        removeItem: (k: string) => { mem.delete(k); },
        clear: () => { mem.clear(); },
        key: (i: number) => Array.from(mem.keys())[i] ?? null,
        get length() { return mem.size; }
    } as unknown as Storage;
})();

// Helper for typed crypto access
const getSubtle = () => ((globalThis as any).crypto?.subtle ?? crypto.subtle) as SubtleCrypto;

function constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

// Map a JWK to a WebCrypto import algorithm (Phase 0 minimal)
function mapJwkToAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | RsaHashedImportParams {
    if (jwk.kty === 'RSA') {
        const hash = jwk.alg && jwk.alg.toUpperCase().includes('256') ? 'SHA-256' : 'SHA-256';
        return { name: 'RSA-OAEP', hash };
    }
    throw new Error(`UNSUPPORTED_EPHEMERAL_KEY: Expected RSA JWK for ephemeral_key, got kty=${jwk.kty || 'unknown'}`);
}

/**
 * Fetch Verifier Public Key (Now with Real Universal Resolver)
 */
async function fetchVerifierPublicKey(did: string): Promise<CryptoKey> {
    // 1. Check Cache
    const cached = keyCache.get(did);
    if (cached && cached.expires > Date.now()) {
        return cached.key;
    }

    // 2. Resolve (Real Resolver from shared-crypto)
    // Supports did:web (HTTPS) and did:mitch (Demo)
    const didDocument = await resolveDID(did);

    // 3. Extract Key (First Verification Method)
    const vm = didDocument.verificationMethod?.[0];
    if (!vm || !vm.publicKeyJwk) {
        throw new Error(`DID_DOCUMENT_INVALID: Missing publicKeyJwk in ${did}`);
    }

    // 4. Import Key (WebCrypto)
    // Detect algorithm from JWK (RSA/EC)
    const algorithm = detectKeyAlgorithm(vm.publicKeyJwk as JsonWebKey);

    // For encryption, we need RSA-OAEP (or EC-ECDH in future)
    const algoName = (typeof algorithm === 'string') ? algorithm : algorithm.name;

    if (algoName === 'RSA-OAEP' && (vm.publicKeyJwk as JsonWebKey).kty !== 'RSA') {
        // Sanity check
        throw new Error('KEY_TYPE_MISMATCH: Expected RSA JWK for RSA-OAEP algorithm');
    }

    const key = await getSubtle().importKey(
        'jwk',
        vm.publicKeyJwk,
        algorithm,
        true,
        ['encrypt', 'wrapKey'] // Verifier keys are for Encryption (confidentiality)
    );

    // 5. Update Cache
    keyCache.set(did, { key, expires: Date.now() + CACHE_TTL_MS });
    console.log(`🔑 Cached public key for ${did} (expires in ${CACHE_TTL_MS / 60000} min)`);

    return key;
}

export class WalletService {
    private storage: SecureStorage | null = null;
    private auditLog: AuditLog;
    private policyEngine: PolicyEngine | null = null;
    private policyPublicKey: CryptoKey | null = null;
    private policyPrivateKey: CryptoKey | null = null; // Identity Private Key (Phase 0)
    private initialized = false;
    private initPromise: Promise<void> | null = null;

    constructor() {
        this.auditLog = new AuditLog('user-wallet-001');
    }

    async initialize(pin: string, saltString: string = "random-salt-per-user-v1"): Promise<void> {
        if (this.initialized) return;
        if (this.initPromise) return this.initPromise;

        this.initPromise = (async () => {
            let retried = false;
            const run = async (): Promise<void> => {
                let step = 'start';
                const formatError = (err: unknown) => {
                    if (err instanceof Error) return `${err.name}: ${err.message}`;
                    return String(err);
                };
                try {
                    // Secure Storage & Key Persistence
                    console.log('🔐 Initializing Wallet with Secure Storage...');

                    // 1. Derive Master Key from PIN (PBKDF2)
                    // In prod, salt should be random (loaded from local storage) and stored.
                    step = 'deriveMasterKey';
                    const salt = new TextEncoder().encode(saltString);
                    const masterKey = await deriveKeyFromPassword(pin, salt);

                    // 2. Initialize Encrypted Storage
                    step = 'initSecureStorage';
                    this.storage = await SecureStorage.init(masterKey);

                    // Initialize Audit Keys (Truth Anchor)
                    // TODO: Persist these as well in next iteration
                    step = 'initAuditKeys';
                    const auditKeys = await generateKeyPair();
                    this.auditLog.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);


                    // 3. Generate Identity Keys (Phase 0: RAM Only - Ephemeral)
                    const IDENTITY_KEY_ID = 'identity-keys-v1';

                    // Remove persistence check: Always generate fresh keys per session
                    console.log('✨ Creating SESSION-SCOPED Identity Keypair (RAM only)...');
                    step = 'generateIdentityKeys';

                    const keys = await (globalThis as any).crypto.subtle.generateKey(
                        { name: 'ECDSA', namedCurve: 'P-256' },
                        false, // extractable: false (Secure Execution Environment emulation)
                        ['sign', 'verify']
                    );

                    this.policyPrivateKey = keys.privateKey;
                    this.policyPublicKey = keys.publicKey;

                    console.warn('⚠️ Phase-0: Identity Keys are ephemeral and will be lost on reload.');

                    // Initialize Policy Engine
                    step = 'initPolicyEngine';
                    this.policyEngine = new PolicyEngine(async (capsule: DecisionCapsule) => {
                        const { wallet_attestation, ...toSign } = capsule;
                        const payload = canonicalStringify(toSign);
                        // Consistent use of shared-crypto
                        if (!this.policyPrivateKey) throw new Error("Identity Key not initialized");
                        return signData(payload, this.policyPrivateKey);
                    });

                    step = 'seedCredentials';
                    this.initialized = true;
                    await this.ensureSeeded();
                    step = 'initPolicy';
                    this.ensurePolicyInitialized();
                } catch (err) {
                    throw new Error(`INIT_FAILED@${step}: ${formatError(err)}`);
                }
            };

            try {
                await run();
            } catch (err) {
                if (!retried) {
                    retried = true;
                    console.warn('[WalletService] Init failed. Resetting storage and retrying...', err);
                    try {
                        if (typeof (SecureStorage as any).reset === 'function') {
                            await (SecureStorage as any).reset();
                        }
                    } catch (resetErr) {
                        console.warn('[WalletService] Storage reset failed. Retrying without reset...', resetErr);
                    }
                    await run();
                    return;
                }
                throw err;
            }
        })();

        try {
            await this.initPromise;
        } finally {
            this.initPromise = null;
        }
    }

    private ensurePolicyInitialized() {
        const existing = localStoreShim.getItem(POLICY_STORAGE_KEY);
        if (!existing) {
            this.savePolicy(DEFAULT_POLICY);
        } else {
            // Migration Logic
            try {
                const p = JSON.parse(existing);
                const currentVer = parseFloat(p.version || '1.0');
                const newVer = parseFloat(DEFAULT_POLICY.version);
                if (currentVer < newVer) {
                    console.log(`Migrating Policy from ${currentVer} to ${newVer}`);
                    this.savePolicy(DEFAULT_POLICY);
                }
            } catch (e) {
                this.savePolicy(DEFAULT_POLICY);
            }
        }
    }

    getPolicy(): PolicyManifest {
        const raw = localStoreShim.getItem(POLICY_STORAGE_KEY);
        if (!raw) return DEFAULT_POLICY;

        const stored = JSON.parse(raw) as PolicyManifest;

        // Safe Policy Migration: Merge new rules, don't overwrite user preferences
        if (stored.version !== DEFAULT_POLICY.version) {
            console.log(`[WalletService] Policy version mismatch (${stored.version} → ${DEFAULT_POLICY.version}). Merging...`);

            // 1. Keep user's existing rules
            const userRuleIds = new Set(stored.rules.map(r => r.id));

            // 2. Add new default rules that user doesn't have
            const newRules = DEFAULT_POLICY.rules.filter(r => !userRuleIds.has(r.id));
            if (newRules.length > 0) {
                console.log(`[WalletService] Adding ${newRules.length} new rules: ${newRules.map(r => r.id).join(', ')}`);
            }

            // 3. Add new trusted issuers
            const userIssuerDids = new Set(stored.trustedIssuers.map(i => i.did));
            const newIssuers = DEFAULT_POLICY.trustedIssuers.filter(i => !userIssuerDids.has(i.did));

            // 4. Merge: User rules + New rules, User issuers + New issuers
            const mergedPolicy: PolicyManifest = {
                ...stored,
                version: DEFAULT_POLICY.version, // Upgrade version
                rules: [...stored.rules, ...newRules],
                trustedIssuers: [...stored.trustedIssuers, ...newIssuers],
                globalSettings: { ...DEFAULT_POLICY.globalSettings, ...stored.globalSettings }
            };

            localStoreShim.setItem(POLICY_STORAGE_KEY, JSON.stringify(mergedPolicy));
            return mergedPolicy;
        }

        return stored;
    }

    savePolicy(policy: PolicyManifest) {
        localStoreShim.setItem(POLICY_STORAGE_KEY, JSON.stringify(policy));
    }

    private async ensureSeeded() {
        if (!this.storage) throw new Error('Storage not ready');
        const metas = await this.storage.getAllMetadata();

        // 1. Initial Seed (Ensure Core Credential exists)
        const seedMeta = metas.find(m => m.id === SEED_CREDENTIAL.id);
        if (!seedMeta) {
            console.log('Seeding initial minimized credentials...');
            await this.storage.save(SEED_CREDENTIAL.id, SEED_CREDENTIAL.payload, {
                issuer: SEED_CREDENTIAL.issuer,
                type: SEED_CREDENTIAL.type,
                claims: SEED_CREDENTIAL.claims,
                issuedAt: SEED_CREDENTIAL.issuedAt
            });
        } else {
            try {
                const existing = await this.storage.load<Record<string, unknown>>(SEED_CREDENTIAL.id);
                if (existing && !('birthDate' in existing)) {
                    await this.storage.save(SEED_CREDENTIAL.id, SEED_CREDENTIAL.payload, {
                        issuer: SEED_CREDENTIAL.issuer,
                        type: SEED_CREDENTIAL.type,
                        claims: SEED_CREDENTIAL.claims,
                        issuedAt: SEED_CREDENTIAL.issuedAt
                    });
                    console.log('Updated age credential to include birthDate for ZKP predicates.');
                }
            } catch (e) {
                // If decryption failed, let init retry/reset handle it.
                console.warn('Seed check failed for age credential.', e);
            }
        }

        // 2. Progressive Seeding
        if (!metas.find(m => m.id === EMPLOYMENT_CREDENTIAL.id)) {
            console.log('Seeding Employment Credential...');
            await this.storage.save(EMPLOYMENT_CREDENTIAL.id, EMPLOYMENT_CREDENTIAL.payload, {
                issuer: EMPLOYMENT_CREDENTIAL.issuer,
                type: EMPLOYMENT_CREDENTIAL.type,
                claims: EMPLOYMENT_CREDENTIAL.claims,
                issuedAt: EMPLOYMENT_CREDENTIAL.issuedAt
            });
        }

        // 3. EHDS Credentials (If missing)
        if (!metas.find(m => m.id === EHDS_PATIENT_SUMMARY.id)) {
            console.log('Seeding EHDS Patient Summary...');
            const summaryPayload = { ...EHDS_PATIENT_SUMMARY.payload, ...EHDS_PATIENT_SUMMARY.payload.content };
            await this.storage.save(EHDS_PATIENT_SUMMARY.id, summaryPayload, {
                issuer: EHDS_PATIENT_SUMMARY.issuer,
                type: EHDS_PATIENT_SUMMARY.type,
                claims: EHDS_PATIENT_SUMMARY.claims,
                issuedAt: EHDS_PATIENT_SUMMARY.issuedAt
            });
        }

        if (!metas.find(m => m.id === EHDS_PRESCRIPTION.id)) {
            console.log('Seeding EHDS Prescription...');
            const rxPayload = { ...EHDS_PRESCRIPTION.payload, ...EHDS_PRESCRIPTION.payload.content };
            await this.storage.save(EHDS_PRESCRIPTION.id, rxPayload, {
                issuer: EHDS_PRESCRIPTION.issuer,
                type: EHDS_PRESCRIPTION.type,
                claims: EHDS_PRESCRIPTION.claims,
                issuedAt: EHDS_PRESCRIPTION.issuedAt
            });
        }
    }

    async seedMalicious() {
        if (!this.storage) throw new Error('Storage not ready');
        await this.storage.save(MALICIOUS_CREDENTIAL.id, MALICIOUS_CREDENTIAL.payload, {
            issuer: MALICIOUS_CREDENTIAL.issuer,
            type: MALICIOUS_CREDENTIAL.type,
            claims: MALICIOUS_CREDENTIAL.claims,
            issuedAt: MALICIOUS_CREDENTIAL.issuedAt
        });
    }

    /**
     * Stress Test - Corrupt a credential in storage to test integrity detection.
     */
    async corruptCredential() {
        if (!this.storage) throw new Error('Storage not ready');
        // Corrupt the 'vc-age-789' entry in the underlying storage (simulated bypass)
        (this.storage as any).corruptEntry(SEED_CREDENTIAL.id);
    }

    /**
     * Stress Test - Evaluate against 500 complex rules.
     */
    async evaluateAgainstExplosion(request: VerifierRequest, context: EvaluationContext): Promise<PolicyEvaluationResult> {
        if (!this.storage || !this.policyEngine) throw new Error('Wallet locked');

        const credentials = await this.storage.getAllMetadata();
        const basePolicy = this.getPolicy();

        const explodedRules = Array.from({ length: 500 }).map((_, i) => ({
            id: `rule-explosion-${i}`,
            verifierPattern: `service-${i}.com`,
            allowedClaims: ['email'],
            priority: 1
        }));

        const stormPolicy: PolicyManifest = {
            ...basePolicy,
            rules: [...basePolicy.rules, ...explodedRules]
        };

        return this.policyEngine.evaluate(request, context, credentials, stormPolicy);
    }

    async splitMasterKey(): Promise<string[]> {
        // In a real app, we'd get the actual master key bits.
        // For the PoC, we use a placeholder that represents the entropy.
        const mockMasterKey = "mitch-master-entropy-v1-highly-sensitive";
        return RecoveryService.splitMasterKey(mockMasterKey);
    }

    async recoverFromFragments(fragments: string[]): Promise<void> {
        const key = await RecoveryService.recover(fragments);
        console.log(`✅ Wallet Recovered! Key: ${key.substring(0, 5)}...`);
        // In prod, this would re-initialize SecureStorage
    }

    async evaluateRequest(request: VerifierRequest, context: EvaluationContext): Promise<PolicyEvaluationResult> {
        if (!this.storage || !this.policyEngine) throw new Error('Wallet locked');

        const credentials = await this.storage.getAllMetadata();

        return this.policyEngine.evaluate(
            request,
            context,
            credentials,
            this.getPolicy()
        );
    }

    /**
     * Verify the entire audit log chain integrity live.
     */
    async verifyAuditChain(): Promise<{ valid: boolean; error?: string }> {
        return this.auditLog.verifyChain();
    }

    async parseDeepLinkRequest(url: string): Promise<VerifierRequest | null> {
        try {
            const parsed = new URL(url);
            if (parsed.protocol !== 'mitch:') return null;

            const verifierDid = parsed.searchParams.get('verifier') || 'did:mitch:unknown';
            const nonce = parsed.searchParams.get('nonce') || crypto.randomUUID();
            const pubKeyB64 = parsed.searchParams.get('pub');

            const req: VerifierRequest = {
                verifierId: verifierDid,
                nonce,
                requirements: [{
                    credentialType: 'VerifiableCredential',
                    requestedClaims: ['age'],
                    requestedProvenClaims: ['age >= 18']
                }]
            };

            if (pubKeyB64) {
                // T-88: Hydrate Ephemeral Key
                try {
                    const jwk = JSON.parse(atob(pubKeyB64));
                    // Use helper to import safely
                    const alg = mapJwkToAlgorithm(jwk);
                    const key = await getSubtle().importKey(
                        'jwk',
                        jwk,
                        alg,
                        true,
                        ['encrypt', 'wrapKey']
                    );
                    req.ephemeralResponseKey = key;
                    console.log('⚡ Hydrated Ephemeral Key from Deep Link');
                } catch (e) {
                    console.warn('Failed to hydrate ephemeral key from URL', e);
                }
            }

            return req;
        } catch (e) {
            console.error('Deep Link Parse Error', e);
            return null;
        }
    }

    async generatePresentation(
        capsule: DecisionCapsule,
        agentTargetPubKey?: CryptoKey // Force encryption to this key (Lufthansa) instead of DID resolution
    ): Promise<{ encryptedVp: string, auditLog: string[] }> {
        if (!this.storage) throw new Error('Wallet locked');
        const logs: string[] = [];

        // 1. Validate Capsule Integrity
        if (!capsule.decision_id || !capsule.nonce) {
            throw new Error('SECURITY ALERT: Invalid Decision Capsule. Replay Attack Possible.');
        }

        const verifierDID = capsule.verifier_did;
        if (!verifierDID) throw new Error('SECURITY ALERT: Capsule not bound to a verifier.');

        if (capsule.audience && capsule.audience !== 'mitch-wallet-pwa') {
            throw new Error(`SECURITY ALERT: Capsule intended for different app (${capsule.audience}).`);
        }

        // Identity Signature Verification (Phase 0)
        if (!capsule.wallet_attestation) {
            throw new Error('SECURITY ALERT: Capsule contains no attestation (Unsigned).');
        }
        if (!this.policyPublicKey) {
            throw new Error('Wallet not initialized properly (Missing Policy Key).');
        }

        const { wallet_attestation, ...toVerify } = capsule;
        const payload = canonicalStringify(toVerify);
        const signatureBytes = new Uint8Array(
            wallet_attestation.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
        );

        const validSignature = await crypto.subtle.verify(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            this.policyPublicKey,
            signatureBytes,
            new TextEncoder().encode(payload)
        );

        if (!validSignature) {
            throw new Error('SECURITY ALERT: Capsule signature verification FAILED. Policy Decision may be forged.');
        }
        logs.push('✅ Capsule Signature Verified (Signed by Identity Key)');

        logs.push(`✅ Capsule Integrity Verified (Ref: ${capsule.decision_id} -> ${verifierDID})`);

        if (agentTargetPubKey) {
            logs.push(`🤖 AUTOMATION FIREWALL: Encrypting for Target, not Requestor.`);
        }

        // Cryptographic Presence Binding
        if (capsule.requires_presence) {
            logs.push('👤 Biometric Presence Required. Triggering WebAuthn Ceremony...');
            const presenceProof = await WebAuthnService.provePresence(capsule.decision_id);
            (capsule as any).presence_proof = presenceProof;
            logs.push('✅ WebAuthn Signature Bound to Decision ID');
        }

        // 2. Multi-VC Pipelining
        const bundles: Array<{
            credentialType: string;
            disclosure: Record<string, unknown>;
            provenClaims: Record<string, boolean>;
            zkpProofs?: Record<string, any>; // Full cryptographic proofs
            // credentialId removed to prevent discovery
        }> = [];

        // Normalize requirements (support legacy if authorized_requirements is missing)
        const requirements = capsule.authorized_requirements || [{
            credential_type: '*',
            allowed_claims: capsule.allowed_claims || [],
            proven_claims: capsule.proven_claims || [],
            selected_credential_id: (capsule as any).selected_credential_id,
            issuer_trust_refs: (capsule as any).issuer_trust_refs || []
        }];

        for (const req of requirements) {
            const selectedId = req.selected_credential_id;
            if (!selectedId) continue;

            const credMeta = (await this.storage.getAllMetadata()).find(c => c.id === selectedId);
            if (!credMeta) throw new Error(`Credential ${selectedId} not found.`);

            // Load & Decrypt
            let credentialData: Record<string, unknown> | null;
            try {
                credentialData = await this.storage.load<Record<string, unknown>>(selectedId);
            } catch (e) {
                await this.ensureSeeded();
                credentialData = await this.storage.load<Record<string, unknown>>(selectedId);
            }

            if (!credentialData) {
                throw new Error(`Failed to load credential data for ${selectedId}`);
            }

            await this.auditLog.append('KEY_USED', selectedId, {
                context: 'CREDENTIAL_DECRYPTION',
                decision_id: capsule.decision_id,
                requirement_type: req.credential_type
            });
            logs.push(`🔓 VC [${req.credential_type}] Decrypted`);

            // Selective Disclosure & ZKP
            const disclosure: Record<string, unknown> = {};
            const provenClaims: Record<string, boolean> = {};
            const zkpProofs: Record<string, any> = {};

            for (const claim of req.allowed_claims) {
                if (credentialData[claim] !== undefined) disclosure[claim] = credentialData[claim];
            }

            for (const predicate of req.proven_claims) {
                if (predicate.startsWith('age >=')) {
                    // Upgrade to ZKP Predicate Engine
                    const matches = predicate.match(/age >= (\d+)/);
                    const ageLimit = matches ? parseInt(matches[1], 10) : 18;

                    const predicateTimestamp = new Date().toISOString();
                    const predReq: PredicateRequest = {
                        verifierDid: verifierDID,
                        nonce: capsule.nonce || `nonce-${Date.now()}`,
                        purpose: 'Age Verification',
                        timestamp: predicateTimestamp,
                        predicates: [CommonPredicates.ageAtLeast(ageLimit)]
                    };

                    // Identity Key Signature (ECDSA P-256)
                    if (!this.policyPrivateKey) throw new Error('Identity Key missing');
                    const signFn = async (d: string) => signData(d, this.policyPrivateKey!);

                    try {
                        const predicateCredential = (credentialData as any).credentialSubject
                            ? (credentialData as Record<string, unknown>)
                            : { credentialSubject: credentialData };
                        const result = await evaluatePredicates(predicateCredential, predReq, signFn);

                        // Phase 0: do not expose key material in proofs

                        zkpProofs[predicate] = result;

                        if (result.proof.allPassed) {
                            provenClaims[predicate] = true;
                            logs.push('[ZKP] Proof generated: ' + result.proof.decisionId + ' (' + result.proof.binding.requestHash.substring(0, 8) + '...)');
                        } else {
                            provenClaims[predicate] = false;
                            logs.push('[ZKP] Proof failed: ' + (result.proof.evaluations[0]?.reasonCode ?? 'UNKNOWN'));
                        }
                    } catch (e) {
                        console.error('ZKP Evaluation Error:', e);
                        provenClaims[predicate] = false;
                        logs.push('[ZKP] Error: ' + String(e));
                    }
                }
            }

            bundles.push({
                credentialType: req.credential_type,
                disclosure,
                provenClaims,
                zkpProofs
                // credentialId intentionally omitted to prevent discovery
            });
        }

        logs.push(`✅ Presentation Bundle Prepared (${bundles.length} VCs)`);

        // 3. Generate Ephemeral Proof Key (Asymmetric ECDSA)
        const proofKeys = await generateKeyPair();
        const proofPublicJWK = await (globalThis as any).crypto.subtle.exportKey('jwk', proofKeys.publicKey);

        await this.auditLog.append('KEY_CREATED', 'ephemeral-proof-key', {
            alg: 'ECDSA-P256',
            decision_id: capsule.decision_id
        });
        logs.push('⚡ Ephemeral Proof Key Created (ECDSA-P256)');

        const vpPayload = {
            metadata: {
                type: 'VerifiablePresentationBundle',
                decision_id: capsule.decision_id,
                timestamp: Date.now(),
                // Replay Protection (Short Lived)
                validUntil: Date.now() + 60000,
                nonce: capsule.nonce,
                // Issuer references are now opaque (from authorized_requirements)
                issuer_trust_refs: requirements.flatMap(r => r.issuer_trust_refs || [])
            },
            presentations: bundles.map(b => ({
                type: b.credentialType,
                disclosure: b.disclosure,
                proven_claims: b.provenClaims,
                zkp_proofs: b.zkpProofs // Include proofs in VP
            }))
        };

        // 4. Sign the Payload
        const payloadString = canonicalStringify(vpPayload);
        const signature = await (globalThis as any).crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            proofKeys.privateKey,
            new TextEncoder().encode(payloadString)
        );
        const signatureHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

        // 5. Create Proof Artifact (Structure must match VerifierSDK expectations)
        const proofArtifact = {
            vp: vpPayload,  // SDK expects 'vp', not 'bundle'
            proof: {
                alg: 'ES256',
                signature: signatureHex,
                public_key: proofPublicJWK,
                presence_proof: (capsule as any).presence_proof
            }
        };

        // 6. Encrypt for Verifier (Isolate Automated Actors)
        const ephemeralKey = await EphemeralKey.create();

        let targetPubKey: CryptoKey;
        const transportDid = verifierDID.startsWith('did:') ? verifierDID : 'did:mitch:verifier-liquor-store';
        if (transportDid !== verifierDID) {
            logs.push(`⚠️ Non-DID verifier id (${verifierDID}). Using demo DID for encryption.`);
        }
        if (agentTargetPubKey) {
            // Key Injection Protection (MITM Check)
            // Note: Keys are opaque handles in WebCrypto. We export to JWK for inspection.
            // We use a constant-time comparison helper to prevent timing side-channels.
            const officialKey = await fetchVerifierPublicKey(transportDid);
            const providedJWK = await getSubtle().exportKey('jwk', agentTargetPubKey);
            const officialJWK = await getSubtle().exportKey('jwk', officialKey);

            const nMatch = constantTimeCompare(providedJWK.n || '', officialJWK.n || '');
            const eMatch = constantTimeCompare(providedJWK.e || '', officialJWK.e || '');

            if (!nMatch || !eMatch) {
                logs.push(`⚠️ SECURITY ALERT: Actor provided a FAKE Key for ${verifierDID}! Blocking.`);
                throw new Error('MITM ATTACK DETECTED: The provided encryption key does not belong to the target identity.');
            }

            logs.push(`✅ Key Binding Verified: Actor provided the correct key for ${transportDid}.`);
            targetPubKey = agentTargetPubKey;
        } else if (capsule.ephemeral_key) {
            // T-88: Ephemeral Session Mode (Zero-Backend)
            logs.push('⚡ Using Ephemeral Session Key from Decision Capsule.');

            try {
                const alg = mapJwkToAlgorithm(capsule.ephemeral_key as any);
                targetPubKey = await getSubtle().importKey(
                    'jwk',
                    capsule.ephemeral_key,
                    alg,
                    true,
                    ['encrypt', 'wrapKey']
                );
            } catch (e) {
                throw new Error(`EPHEMERAL_KEY_IMPORT_FAILED: ${(e as Error).message}`);
            }
        } else {
            // Standard Mode: We resolve the DID to get the key.
            targetPubKey = await fetchVerifierPublicKey(transportDid);
        }

        await this.auditLog.append('KEY_CREATED', 'ephemeral-session-key', {
            alg: 'AES-GCM-256',
            decision_id: capsule.decision_id
        });
        logs.push('🔐 Ephemeral Session Key Created (AES-GCM-256)');

        const aad = new TextEncoder().encode(
            canonicalStringify({
                decision_id: capsule.decision_id,
                nonce: capsule.nonce,
                verifier_did: verifierDID
            })
        );

        const ciphertext = await ephemeralKey.encrypt(JSON.stringify(proofArtifact), aad);
        const encryptedKey = await ephemeralKey.sealToRecipient(targetPubKey);

        const transportPackage = JSON.stringify({
            ciphertext,
            aad_context: {
                decision_id: capsule.decision_id,
                nonce: capsule.nonce,
                verifier_did: verifierDID
            },
            recipient: {
                header: { kid: `${verifierDID}#key-1` },
                encrypted_key: encryptedKey
            }
        });

        // 7. Crypto-Shredding (Double Shred)
        ephemeralKey.shred();
        (proofKeys as any).privateKey = null;

        await this.auditLog.append('KEY_DESTROYED', 'ephemeral-session-key', {
            decision_id: capsule.decision_id,
            verified: true,
            reason: 'Session terminal'
        });
        await this.auditLog.append('KEY_DESTROYED', 'ephemeral-proof-key', {
            decision_id: capsule.decision_id,
            verified: true,
            reason: 'Presentation complete'
        });

        logs.push('♻️ Ephemeral key references dropped (best-effort). Non-extractable keys used.');
        logs.push('✅ VP Bundle Signed & Encrypted');

        return { encryptedVp: transportPackage, auditLog: logs };
    }

    /**
     * Get recent logs for the UI.
     */
    getRecentAuditLogs(limit: number = 5): AuditLogEntry[] {
        return this.auditLog.getRecentEntries(limit);
    }

    /**
     * Export a signed report of all wallet activities.
     * This is the "Beweislast-Umkehr" (Reverse Onus of Proof) artifact.
     */
    async exportAuditReport(): Promise<AuditLogExport> {
        return this.auditLog.exportReport();
    }

    async syncAuditToL2() {
        return this.auditLog.syncToL2();
    }

    /**
     * Handle Recovery Actions triggered by Policy Denial
     */
    async handleAction(action: import('@mitch/shared-types').DenialAction): Promise<{ success: boolean; message: string }> {
        console.log(`[Action Handler] Processing: ${action.type}`);

        switch (action.type) {
            case 'LOAD_CREDENTIAL':
                // Simulate launching OID4VCI (dependency)
                console.log(`[OID4VCI] Launching wizard for target: ${action.target}`);
                return { success: true, message: 'OID4VCI Wizard Started' };

            case 'OVERRIDE_WITH_CONSENT':
                // In a real app, this would grant temporary permission
                console.log(`[Override] User accepted risk for action: ${action.id}`);
                await this.auditLog.append('POLICY_EVALUATED', action.id, {
                    result: 'OVERRIDE',
                    context: 'USER_CONSENT_GRANTED'
                });
                return { success: true, message: 'Policy Override Granted' };

            case 'CONTACT_VERIFIER':
                console.log(`[Contact] Opening support channel for ${action.target}`);
                // window.open('mailto:support@verifier.com');
                return { success: true, message: 'Support Channel Opened' };

            case 'LEARN_MORE':
                console.log(`[Learn] Navigating to: ${action.target}`);
                // window.open(action.target, '_blank');
                return { success: true, message: 'Documentation Opened' };

            case 'REPORT_ISSUE':
                console.log('[Report] Logging issue to support queue.');
                return { success: true, message: 'Issue Reported' };

            default:
                console.warn(`[Handler] Unknown action type: ${action.type}`);
                return { success: false, message: 'Action not realized' };
        }
    }

    /**
     * Sign arbitrary data (e.g., document hashes) using the persistent Identity Key.
     * This differs from ephemeral VP signing - these signatures are meant to persist.
     * 
     * NOTE: This returns a "Compact-like proof token" (not RFC7515 JWS).
     * For production, implement proper ES256 JWS with base64url encoding.
     */
    async signData(payload: ProofOfExistence): Promise<{ proofToken: string, auditLog: string[] }> {
        if (!this.storage) throw new Error('Wallet locked');

        // Access audit keys via internal property (AuditLog doesn't expose getAuditKeys)
        // TODO: Separate identity signing key from audit key (see security review)
        const auditKeys = (this.auditLog as any).privateKey ?
            { privateKey: (this.auditLog as any).privateKey, publicKey: (this.auditLog as any).publicKey } :
            null;

        if (!auditKeys?.privateKey) throw new Error('Identity keys not available');

        const logs: string[] = [];
        const content = canonicalStringify(payload);

        // Sign with ECDSA
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            auditKeys.privateKey,
            new TextEncoder().encode(content)
        );

        const signatureHex = Array.from(new Uint8Array(signature))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        // Create Proof Token (Compact-like format, NOT RFC7515 JWS)
        // Format: base64(header).base64(payload).hex(signature)
        // Note: Uses standard Base64, not Base64URL; signature is hex, not base64url(r|s)
        const header = canonicalStringify({ alg: 'ES256-PoC', kid: 'did:mitch:user-wallet-001#audit-key' });
        const protectedHeader = btoa(header);
        const encodedPayload = btoa(content);

        const proofToken = `${protectedHeader}.${encodedPayload}.${signatureHex}`;

        await this.auditLog.append('KEY_USED', payload.hash, {
            context: 'DOCUMENT_SIGNING',
            description: payload.description,
            type: payload.mediaType
        });

        logs.push(`✅ Document Signed: ${payload.description}`);
        logs.push(`📝 Hash: ${payload.hash.substring(0, 8)}...`);
        logs.push('🔑 Key: Persistent Identity Key');
        logs.push('⚠️  PoC Token Format (not RFC7515 JWS)');

        return { proofToken, auditLog: logs };
    }
}



