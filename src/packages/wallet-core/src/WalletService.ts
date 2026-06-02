import { 
    deriveKeyFromPassword,
    generateKeyPair,
    WebAuthnService
} from '@mitch/shared-crypto';
import { SecureStorage, BrowserIndexedDBAdapter, InMemoryStorageAdapter } from '@mitch/secure-storage';
import { AuditLog } from '@mitch/audit-log';
import { PolicyEngine } from '@mitch/policy-engine';
import { 
    StoredCredentialMetadata, 
    PolicyManifest, 
    VerifierRequest, 
    PolicyEvaluationResult,
    DecisionCapsule
} from '@mitch/shared-types';
import { EvaluationContext } from '@mitch/policy-engine';

import { ICredentialRepository } from './ICredentialRepository';
import { EncryptedCredentialRepository } from './EncryptedCredentialRepository';
import { IPolicyEvaluator } from './IPolicyEvaluator';
import { MitchPolicyEvaluator } from './MitchPolicyEvaluator';
import { IPresentationManager } from './IPresentationManager';

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
    
    private initialized = false;

    constructor(
        credentials: ICredentialRepository,
        policy: IPolicyEvaluator,
        auditLog: AuditLog
    ) {
        this.credentials = credentials;
        this.policy = policy;
        this.auditLog = auditLog;
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
        const auditLog = new AuditLog('user-wallet-001');
        const auditKeys = await generateKeyPair();
        auditLog.setAuditKeys(auditKeys.privateKey, auditKeys.publicKey);

        // 3. Policy
        const engine = new PolicyEngine(async (capsule: DecisionCapsule) => {
            // Placeholder for identity signing (T-31)
            return "mock-signature";
        });
        const policyEvaluator = new MitchPolicyEvaluator(engine, localStorage);

        return new WalletService(credRepo, policyEvaluator, auditLog);
    }

    async initialize(): Promise<void> {
        if (this.initialized) return;
        this.initialized = true;
    }

    async evaluateRequest(request: VerifierRequest, context: EvaluationContext): Promise<PolicyEvaluationResult> {
        const credentials = await this.credentials.listMetadata();
        const policy = this.policy.getPolicy();
        return this.policy.evaluate(request, context, credentials, policy);
    }
}
