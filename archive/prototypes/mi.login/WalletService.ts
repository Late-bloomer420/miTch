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
    signData
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
    claims: ['age'],
    payload: {
        age: 24, // Raw PII in Secure Storage
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

// T-30: EHDS Sample Credentials
const EHDS_PATIENT_SUMMARY = {
    id: 'vc-ehds-summary-001',
    issuer: 'did:example:ehealth-authority',
    type: ['VerifiableCredential', 'HealthRecord', 'PatientSummary'],
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

let verifierKeyPair: CryptoKeyPair | null = null;

// T-35b: DID Resolution Cache
const keyCache = new Map<string, { key: CryptoKey, expires: number }>();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 Minutes

/**
 * T-81: Universal DID Resolver
 * Supports: did:web (HTTPS), did:mitch (demo), fallback to mock
 */
interface DIDDocument {
    id: string;
    verificationMethod: Array<{
        id: string;
        type: string;
        controller: string;
        publicKeyJwk: JsonWebKey;
    }>;
}

async function resolveDID(did: string): Promise<DIDDocument> {
    // 1. did:web Resolution (Production-Grade)
    if (did.startsWith('did:web:')) {
        const domain = did.replace('did:web:', '').replace(/:/g, '/');
        const url = `https://${domain}/.well-known/did.json`;
        
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const doc = await response.json();
            console.log(`✅ Resolved ${did} via HTTPS`);
            return doc;
        } catch (e) {
            console.error(`[DID Resolver] Failed to resolve ${did}:`, e);
            throw new Error(`DID_RESOLUTION_FAILED: ${did}`);
        }
    }

    // 2. did:mitch Resolution (Demo Backend)
    if (did.startsWith('did:mitch:')) {
        const backendUrl = 'http://localhost:3002/did.json';
        try {
            const response = await fetch(backendUrl);
            if (!response.ok) throw new Error(`Backend offline`);
            const doc = await response.json();
            console.log(`✅ Resolved ${did} via Demo Backend`);
            return doc;
        } catch (e) {
            console.warn(`[DID Resolver] Demo backend unreachable, using mock for ${did}`);
            return generateMockDIDDocument(did);
        }
    }

    // 3. Fallback: Mock (for offline demos / unit tests)
    console.warn(`⚠️ Unsupported DID method: ${did}. Using mock.`);
    return generateMockDIDDocument(did);
}

function generateMockDIDDocument(did: string): DIDDocument {
    // This should NEVER happen in production
    console.error(`🚨 MOCK DID DOCUMENT GENERATED FOR ${did} - NOT FOR PRODUCTION!`);
    
    return {
        id: did,
        verificationMethod: [{
            id: `${did}#key-1`,
            type: 'JsonWebKey2020',
            controller: did,
            publicKeyJwk: {
                kty: 'RSA',
                n: 'mock-n',
                e: 'AQAB'
            }
        }]
    };
}

/**
 * T-81: Detect key algorithm from JWK
 */
function detectKeyAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier {
    switch (jwk.kty) {
        case 'RSA':
            return { name: 'RSA-OAEP', hash: 'SHA-256' };
        case 'EC':
            return { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' };
        case 'OKP':
            throw new Error('UNSUPPORTED_KEY_TYPE: OKP (EdDSA) not yet supported');
        default:
            throw new Error(`UNSUPPORTED_KEY_TYPE: ${jwk.kty}`);
    }
}

/**
 * T-81: Fetch Verifier Public Key (Now with Universal Resolver)
 */
async function fetchVerifierPublicKey(did: string): Promise<CryptoKey> {
    // 1. Check Cache
    const cached = keyCache.get(did);
    if (cached && cached.expires > Date.now()) {
        return cached.key;
    }

    // 2. Resolve DID Document
    const didDocument = await resolveDID(did);

    // 3. Extract Verification Method
    const vm = didDocument.verificationMethod?.[0];
    if (!vm || !vm.publicKeyJwk) {
        throw new Error(`DID_DOCUMENT_INVALID: Missing publicKeyJwk in ${did}`);
    }

    // 4. Detect Algorithm & Import Key
    const algorithm = detectKeyAlgorithm(vm.publicKeyJwk);
    
    // For encryption, we need RSA-OAEP
    if (vm.publicKeyJwk.kty !== 'RSA') {
        throw new Error(`KEY_TYPE_MISMATCH: Expected RSA for encryption, got ${vm.publicKeyJwk.kty}`);
    }

    const key = await crypto.subtle.importKey(
        'jwk',
        vm.publicKeyJwk,
        algorithm,
        true,
        ['encrypt', 'wrapKey']
    );

    // 5. Cache
    keyCache.set(did, { key, expires: Date.now() + CACHE_TTL_MS });
    console.log(`🔑 Cached public key for ${did} (expires in ${CACHE_TTL_MS / 60000} min)`);

    return key;
}

export class WalletService {
    private storage: SecureStorage | null = null;
    private auditLog: AuditLog;
    private policyEngine: PolicyEngine | null = null;
    private policyPublicKey: CryptoKey | null = null;
    private policyPrivateKey: CryptoKey | null = null;
    private initialized = false;

    constructor() {
        this.auditLog = new AuditLog('user-wallet-001');
    }

    async initialize(pin: string, saltString: string = "random-salt-per-user-v1"): Promise<void> {
        if (this.initialized) return;

        console.log('🔐 Initializing Wallet with Secure Storage...');

        // T-74: Derive Master Key from PIN (PBKDF2)
        const salt = new TextEncoder().encode(saltString);
        const masterKey = await deriveKeyFromPassword(pin, salt);

        // T-74: Initialize Encrypted Storage (IndexedDB + AES-GCM)
        this.storage = await SecureStorage.init(masterKey);

        // Initialize Audit Keys (TODO: Persist in next iteration)
        const auditKeys = await generateKeyPair();
        this.auditLog.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        // T-74: Load or Generate Enclave Identity Keys
        const ENCLAVE_KEY_ID = 'enclave-identity-keys-v1';
        type EnclaveKeySet = { privateJwk: JsonWebKey; publicJwk: JsonWebKey };

        const storedKeys = await this.storage.load<EnclaveKeySet>(ENCLAVE_KEY_ID);

        if (storedKeys) {
            console.log('📂 Loaded existing Enclave Keys from Secure Storage.');
            this.policyPrivateKey = await crypto.subtle.importKey(
                'jwk',
                storedKeys.privateJwk,
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,
                ['sign']
            );
            this.policyPublicKey = await crypto.subtle.importKey(
                'jwk',
                storedKeys.publicJwk,
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['verify']
            );
        } else {
            console.log('✨ Creating NEW Enclave Identity...');
            const keys = await generateKeyPair();
            this.policyPrivateKey = keys.privateKey;
            this.policyPublicKey = keys.publicKey;

            // Persist Keys
            const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
            const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);

            await this.storage.save(ENCLAVE_KEY_ID, { privateJwk, publicJwk }, {
                type: ['SystemKey', 'EnclaveIdentity'],
                issuer: 'System',
                issuedAt: new Date().toISOString(),
                claims: []
            });
            console.log('💾 Enclave Keys persisted securely.');
        }

        // Initialize Policy Engine
        this.policyEngine = new PolicyEngine(async (capsule: DecisionCapsule) => {
            const { wallet_attestation, ...toSign } = capsule;
            const payload = canonicalStringify(toSign);
            if (!this.policyPrivateKey) throw new Error("Enclave Key not initialized");
            return signData(payload, this.policyPrivateKey);
        });

        this.initialized = true;
        await this.ensureSeeded();
        this.ensurePolicyInitialized();
    }

    private ensurePolicyInitialized() {
        const existing = localStorage.getItem(POLICY_STORAGE_KEY);
        if (!existing) {
            this.savePolicy(DEFAULT_POLICY);
        } else {
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
        const raw = localStorage.getItem(POLICY_STORAGE_KEY);
        if (!raw) return DEFAULT_POLICY;

        const stored = JSON.parse(raw) as PolicyManifest;

        if (stored.version !== DEFAULT_POLICY.version) {
            console.log(`[WalletService] Policy version mismatch (${stored.version} → ${DEFAULT_POLICY.version}). Merging...`);

            const userRuleIds = new Set(stored.rules.map(r => r.id));
            const newRules = DEFAULT_POLICY.rules.filter(r => !userRuleIds.has(r.id));
            if (newRules.length > 0) {
                console.log(`[WalletService] Adding ${newRules.length} new rules: ${newRules.map(r => r.id).join(', ')}`);
            }

            const userIssuerDids = new Set(stored.trustedIssuers.map(i => i.did));
            const newIssuers = DEFAULT_POLICY.trustedIssuers.filter(i => !userIssuerDids.has(i.did));

            const mergedPolicy: PolicyManifest = {
                ...stored,
                version: DEFAULT_POLICY.version,
                rules: [...stored.rules, ...newRules],
                trustedIssuers: [...stored.trustedIssuers, ...newIssuers],
                globalSettings: { ...DEFAULT_POLICY.globalSettings, ...stored.globalSettings }
            };

            localStorage.setItem(POLICY_STORAGE_KEY, JSON.stringify(mergedPolicy));
            return mergedPolicy;
        }

        return stored;
    }

    savePolicy(policy: PolicyManifest) {
        localStorage.setItem(POLICY_STORAGE_KEY, JSON.stringify(policy));
    }

    private async ensureSeeded() {
        if (!this.storage) throw new Error('Storage not ready');
        const metas = await this.storage.getAllMetadata();

        if (!metas.find(m => m.id === SEED_CREDENTIAL.id)) {
            console.log('Seeding initial minimized credentials...');
            await this.storage.save(SEED_CREDENTIAL.id, SEED_CREDENTIAL.payload, {
                issuer: SEED_CREDENTIAL.issuer,
                type: SEED_CREDENTIAL.type,
                claims: SEED_CREDENTIAL.claims,
                issuedAt: SEED_CREDENTIAL.issuedAt
            });
        }

        if (!metas.find(m => m.id === EMPLOYMENT_CREDENTIAL.id)) {
            console.log('Seeding Employment Credential (T-29)...');
            await this.storage.save(EMPLOYMENT_CREDENTIAL.id, EMPLOYMENT_CREDENTIAL.payload, {
                issuer: EMPLOYMENT_CREDENTIAL.issuer,
                type: EMPLOYMENT_CREDENTIAL.type,
                claims: EMPLOYMENT_CREDENTIAL.claims,
                issuedAt: EMPLOYMENT_CREDENTIAL.issuedAt
            });
        }

        if (!metas.find(m => m.id === EHDS_PATIENT_SUMMARY.id)) {
            console.log('Seeding EHDS Patient Summary (T-30)...');
            const summaryPayload = { ...EHDS_PATIENT_SUMMARY.payload, ...EHDS_PATIENT_SUMMARY.payload.content };
            await this.storage.save(EHDS_PATIENT_SUMMARY.id, summaryPayload, {
                issuer: EHDS_PATIENT_SUMMARY.issuer,
                type: EHDS_PATIENT_SUMMARY.type,
                claims: EHDS_PATIENT_SUMMARY.claims,
                issuedAt: EHDS_PATIENT_SUMMARY.issuedAt
            });
        }

        if (!metas.find(m => m.id === EHDS_PRESCRIPTION.id)) {
            console.log('Seeding EHDS Prescription (T-30)...');
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

    async corruptCredential() {
        if (!this.storage) throw new Error('Storage not ready');
        (this.storage as any).corruptEntry(SEED_CREDENTIAL.id);
    }

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
        const mockMasterKey = "mitch-master-entropy-v1-highly-sensitive";
        return RecoveryService.splitMasterKey(mockMasterKey);
    }

    async recoverFromFragments(fragments: string[]): Promise<void> {
        const key = await RecoveryService.recover(fragments);
        console.log(`✅ Wallet Recovered! Key: ${key.substring(0, 5)}...`);
    }

    async evaluateRequest(request: VerifierRequest, context: EvaluationContext): Promise<PolicyEvaluationResult> {
        if (!this.storage || !this.policyEngine) throw new Error('Wallet locked');
        const credentials = await this.storage.getAllMetadata();
        return this.policyEngine.evaluate(request, context, credentials, this.getPolicy());
    }

    async verifyAuditChain(): Promise<{ valid: boolean; error?: string }> {
        return this.auditLog.verifyChain();
    }

    async generatePresentation(
        capsule: DecisionCapsule,
        agentTargetPubKey?: CryptoKey
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

        // T-12: Enclave Signature Verification
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
        logs.push('✅ Capsule Attestation Verified (Signed by Enclave)');
        logs.push(`✅ Capsule Integrity Verified (Ref: ${capsule.decision_id} -> ${verifierDID})`);

        if (agentTargetPubKey) {
            logs.push(`🤖 AI FIREWALL MODE: Encrypting for Target, not Requestor.`);
        }

        // T-23: Cryptographic Presence Binding
        if (capsule.requires_presence) {
            logs.push('👤 Biometric Presence Required. Triggering WebAuthn Ceremony...');
            const presenceProof = await WebAuthnService.provePresence(capsule.decision_id);
            (capsule as any).presence_proof = presenceProof;
            logs.push('✅ WebAuthn Signature Bound to Decision ID');
        }

        // 2. T-29: Multi-VC Pipelining
        const bundles: Array<{
            credentialType: string;
            disclosure: Record<string, unknown>;
            provenClaims: Record<string, boolean>;
            zkpProofs?: Record<string, any>;
        }> = [];

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

            const disclosure: Record<string, unknown> = {};
            const provenClaims: Record<string, boolean> = {};
            const zkpProofs: Record<string, any> = {};

            for (const claim of req.allowed_claims) {
                if (credentialData[claim] !== undefined) disclosure[claim] = credentialData[claim];
            }

            for (const predicate of req.proven_claims) {
                if (predicate.startsWith('age >=')) {
                    const matches = predicate.match(/age >= (\d+)/);
                    const ageLimit = matches ? parseInt(matches[1], 10) : 18;

                    const predReq: PredicateRequest = {
                        verifierDid: verifierDID,
                        nonce: capsule.nonce || `nonce-${Date.now()}`,
                        purpose: 'Age Verification',
                        timestamp: new Date().toISOString(),
                        predicates: [CommonPredicates.ageAtLeast(ageLimit)]
                    };

                    if (!this.policyPrivateKey) throw new Error('Enclave Key missing');
                    const signFn = async (d: string) => signData(d, this.policyPrivateKey!);

                    try {
                        const result = await evaluatePredicates(credentialData, predReq, signFn);

                        if (this.policyPublicKey) {
                            const enclaveKeyJwk = await crypto.subtle.exportKey('jwk', this.policyPublicKey);
                            (result as any).enclaveKey = enclaveKeyJwk;
                        }

                        zkpProofs[predicate] = result;

                        if (result.allPassed) {
                            provenClaims[predicate] = true;
                            logs.push(`🛡️ ZKP Proof Generated: ${result.decisionId} (${result.binding.requestHash.substring(0, 8)}...)`);
                        } else {
                            provenClaims[predicate] = false;
                            logs.push(`❌ ZKP Proof Failed: ${result.evaluations[0]?.reasonCode}`);
                        }
                    } catch (e) {
                        console.error('ZKP Evaluation Error:', e);
                        provenClaims[predicate] = false;
                        logs.push(`❌ ZKP Error: ${String(e)}`);
                    }
                }
            }

            bundles.push({
                credentialType: req.credential_type,
                disclosure,
                provenClaims,
                zkpProofs
            });
        }

        logs.push(`✅ Presentation Bundle Prepared (${bundles.length} VCs)`);

        // 3. Generate Ephemeral Proof Key
        const proofKeys = await generateKeyPair();
        const proofPublicJWK = await crypto.subtle.exportKey('jwk', proofKeys.publicKey);

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
                validUntil: Date.now() + 60000,
                nonce: capsule.nonce,
                issuer_trust_refs: requirements.flatMap(r => r.issuer_trust_refs || [])
            },
            presentations: bundles.map(b => ({
                type: b.credentialType,
                disclosure: b.disclosure,
                proven_claims: b.provenClaims,
                zkp_proofs: b.zkpProofs
            }))
        };

        // 4. Sign the Payload
        const payloadString = canonicalStringify(vpPayload);
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            proofKeys.privateKey,
            new TextEncoder().encode(payloadString)
        );
        const signatureHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

        const proofArtifact = {
            vp: vpPayload,
            proof: {
                alg: 'ES256',
                signature: signatureHex,
                public_key: proofPublicJWK,
                presence_proof: (capsule as any).presence_proof
            }
        };

        // 6. Encrypt for Verifier
        const ephemeralKey = await EphemeralKey.create();

        let targetPubKey: CryptoKey;
        if (agentTargetPubKey) {
            const officialKey = await fetchVerifierPublicKey(verifierDID);
            const providedJWK = await crypto.subtle.exportKey('jwk', agentTargetPubKey);
            const officialJWK = await crypto.subtle.exportKey('jwk', officialKey);

            const nMatch = constantTimeCompare(providedJWK.n || '', officialJWK.n || '');
            const eMatch = constantTimeCompare(providedJWK.e || '', officialJWK.e || '');

            if (!nMatch || !eMatch) {
                logs.push(`⚠️ SECURITY ALERT: Agent provided a FAKE Key for ${verifierDID}! Blocking.`);
                throw new Error('MITM ATTACK DETECTED: The provided encryption key does not belong to the target identity.');
            }

            logs.push(`✅ Key Binding Verified: Agent provided the correct key for ${verifierDID}.`);
            targetPubKey = agentTargetPubKey;
        } else {
            targetPubKey = await fetchVerifierPublicKey(verifierDID);
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

        // 7. Crypto-Shredding
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

        logs.push('🔥 All Ephemeral Keys SHREDDED (Session & Proof)');
        logs.push('✅ VP Bundle Signed & Encrypted');

        return { encryptedVp: transportPackage, auditLog: logs };
    }

    getRecentAuditLogs(limit: number = 5): AuditLogEntry[] {
        return this.auditLog.getRecentEntries(limit);
    }

    async exportAuditReport(): Promise<AuditLogExport> {
        return this.auditLog.exportReport();
    }

    async syncAuditToL2() {
        return this.auditLog.syncToL2();
    }

    async handleAction(action: import('@mitch/shared-types').DenialAction): Promise<{ success: boolean; message: string }> {
        console.log(`[Action Handler] Processing: ${action.type}`);

        switch (action.type) {
            case 'LOAD_CREDENTIAL':
                console.log(`[OID4VCI] Launching wizard for target: ${action.target}`);
                return { success: true, message: 'OID4VCI Wizard Started' };

            case 'OVERRIDE_WITH_CONSENT':
                console.log(`[Override] User accepted risk for action: ${action.id}`);
                await this.auditLog.append('POLICY_EVALUATED', action.id, {
                    result: 'OVERRIDE',
                    context: 'USER_CONSENT_GRANTED'
                });
                return { success: true, message: 'Policy Override Granted' };

            case 'CONTACT_VERIFIER':
                console.log(`[Contact] Opening support channel for ${action.target}`);
                return { success: true, message: 'Support Channel Opened' };

            case 'LEARN_MORE':
                console.log(`[Learn] Navigating to: ${action.target}`);
                return { success: true, message: 'Documentation Opened' };

            case 'REPORT_ISSUE':
                console.log('[Report] Logging issue to support queue.');
                return { success: true, message: 'Issue Reported' };

            default:
                console.warn(`[Handler] Unknown action type: ${action.type}`);
                return { success: false, message: 'Action not realized' };
        }
    }

    async signData(payload: ProofOfExistence): Promise<{ proofToken: string, auditLog: string[] }> {
        if (!this.storage) throw new Error('Wallet locked');

        const auditKeys = (this.auditLog as any).privateKey ?
            { privateKey: (this.auditLog as any).privateKey, publicKey: (this.auditLog as any).publicKey } :
            null;

        if (!auditKeys?.privateKey) throw new Error('Identity keys not available');

        const logs: string[] = [];
        const content = canonicalStringify(payload);

        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            auditKeys.privateKey,
            new TextEncoder().encode(content)
        );

        const signatureHex = Array.from(new Uint8Array(signature))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

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
        logs.push('🔑 Key: Persistent Identity Key (Audit Key)');
        logs.push('⚠️  PoC Token Format (not RFC7515 JWS)');

        return { proofToken, auditLog: logs };
    }
}

function constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
        mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    }
    return mismatch === 0;
}
