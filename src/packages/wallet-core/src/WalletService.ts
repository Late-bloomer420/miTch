import { 
    deriveKeyFromPassword,
    generateKeyPair,
    WebAuthnService
} from '@mitch/shared-crypto';
import { SecureStorage, BrowserIndexedDBAdapter } from '@mitch/secure-storage';
import { AuditLog } from '@mitch/audit-log';
import { PolicyEngine, type EvaluationContext } from '@mitch/policy-engine';
import { 
    StoredCredentialMetadata, 
    PolicyManifest, 
    VerifierRequest, 
    PolicyEvaluationResult,
    DecisionCapsule,
    AuditLogEntry
} from '@mitch/shared-types';

import { ICredentialRepository } from './ICredentialRepository';
import { EncryptedCredentialRepository } from './EncryptedCredentialRepository';
import { IPolicyEvaluator } from './IPolicyEvaluator';
import { MitchPolicyEvaluator } from './MitchPolicyEvaluator';
import { IPresentationManager } from './IPresentationManager';
import { MitchPresentationManager } from './MitchPresentationManager';

/**
 * Unified Wallet Facade (Phase 2.2 Modular).
 * 
 * This class coordinates sub-services to provide a high-level API
 * for the Wallet PWA. It delegates storage, policy, and presentation
 * logic to specialized repositories.
 */
export class WalletService {
    public readonly credentials: ICredentialRepository;
    public readonly policy: IPolicyEvaluator;
    public readonly auditLog: AuditLog;
    public readonly presentation: IPresentationManager;
    
    private initialized = false;
    private auditPublicKey: CryptoKey | null = null;

    constructor(
        credentials: ICredentialRepository,
        policy: IPolicyEvaluator,
        auditLog: AuditLog,
        presentation: IPresentationManager,
        auditPublicKey?: CryptoKey
    ) {
        this.credentials = credentials;
        this.policy = policy;
        this.auditLog = auditLog;
        this.presentation = presentation;
        this.auditPublicKey = auditPublicKey || null;
    }

    /**
     * Standard Factory for Browser environment.
     */
    static async createBrowserWallet(pin: string, salt: string): Promise<WalletService> {
        const saltBytes = new TextEncoder().encode(salt);
        const masterKey = await deriveKeyFromPassword(pin, saltBytes);
        
        // 1. Storage
        const storage = await SecureStorage.init(masterKey, new BrowserIndexedDBAdapter());
        const credRepo = new EncryptedCredentialRepository(storage);

        // 2. Audit
        const auditLog = new AuditLog('user-wallet-001', { useProductionStorage: true });
        await auditLog.initialize();
        const auditKeys = await generateKeyPair();
        auditLog.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        // 3. Policy
        const engine = new PolicyEngine(async (_capsule: DecisionCapsule) => {
            // Placeholder for identity signing (T-31)
            return "mock-signature";
        });
        const policyEvaluator = new MitchPolicyEvaluator(engine, localStorage);

        // 4. Presentation
        const presentation = new MitchPresentationManager(credRepo, auditLog);

        return new WalletService(credRepo, policyEvaluator, auditLog, presentation, auditKeys.publicKey);
    }

    async initialize(): Promise<void> {
        if (this.initialized) return;
        this.initialized = true;
    }

    /**
     * High-level evaluation entry point.
     */
    async evaluateRequest(request: VerifierRequest, context: EvaluationContext): Promise<PolicyEvaluationResult> {
        const credentials = await this.credentials.listMetadata();
        const policy = this.policy.getPolicy();
        return this.policy.evaluate(request, context, credentials, policy);
    }

    /**
     * Proxy for credential listing (metadata).
     */
    async getCredentials(): Promise<StoredCredentialMetadata[]> {
        return this.credentials.listMetadata();
    }

    /**
     * Proxy for policy retrieval.
     */
    getPolicy(): PolicyManifest {
        return this.policy.getPolicy();
    }

    /**
     * Proxy for audit logs.
     */
    getRecentAuditLogs(limit: number): AuditLogEntry[] {
        return this.auditLog.getRecentEntries(limit);
    }

    /**
     * VP Generation Bridge.
     */
    async generatePresentation(
        capsule: DecisionCapsule,
        agentTargetPubKey?: CryptoKey
    ): Promise<{ encryptedVp: string, auditLog: string[] }> {
        const result = await this.presentation.generatePresentation(capsule, agentTargetPubKey);
        return { encryptedVp: result.encryptedVp, auditLog: result.logs };
    }

    /**
     * Identity Firewall Event Recording.
     */
    async recordIdentityFirewallEvents(
        decisionId: string | undefined,
        verifierDid: string | undefined,
        trackers: any[]
    ): Promise<AuditLogEntry[]> {
        if (!decisionId || !verifierDid) return [];
        
        const entries: AuditLogEntry[] = [];
        for (const tracker of trackers) {
            const entry = await this.auditLog.append('IDENTITY_ACCESS_DETECTED', decisionId, {
                verifierDid,
                tracker: tracker.actor,
                type: tracker.type
            });
            entries.push(entry);
        }
        return entries;
    }

    /**
     * Get the identity public key for proximity presentation.
     */
    getIdentityPublicKey(): CryptoKey | null {
        return this.auditPublicKey;
    }

    /**
     * ISO 18013-5 Proximity Response Bridge.
     */
    async generateProximityResponse(
        credId: string,
        requestedElements: { ns: string, element: string }[],
        sessionTranscript: any
    ): Promise<Uint8Array> {
        return this.presentation.generateProximityResponse(credId, requestedElements, sessionTranscript);
    }

    /**
     * Placeholder for key splitting (Phase 5).
     */
    async splitMasterKey(): Promise<string[]> {
        // PoC Stub: In production this uses Shamir Secret Sharing
        return ["share-1-mock", "share-2-mock", "share-3-mock"];
    }

    /**
     * Placeholder for key recovery (Phase 5).
     */
    async recoverFromFragments(fragments: string[]): Promise<void> {
        // PoC Stub
        console.log("Wallet recovered via fragments:", fragments);
    }
}
