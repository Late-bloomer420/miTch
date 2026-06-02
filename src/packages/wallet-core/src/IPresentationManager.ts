import { 
    DecisionCapsule, 
    AuditLogEntry 
} from '@mitch/shared-types';

/**
 * Interface for Verifiable Presentation generation and cryptographic cleanup.
 * Extracted from WalletService for Phase 2.2 decomposition.
 */
export interface IPresentationManager {
    /**
     * Generate an encrypted Verifiable Presentation bundle.
     */
    generatePresentation(
        capsule: DecisionCapsule,
        agentTargetPubKey?: CryptoKey
    ): Promise<{ encryptedVp: string, logs: string[] }>;

    /**
     * Log a successful transmission.
     */
    logVpSent(decisionId: string, metadata: Record<string, unknown>): Promise<void>;

    /**
     * Generate an ISO 18013-5 DeviceResponse for proximity presentation.
     */
    generateProximityResponse(
        credId: string,
        requestedElements: { ns: string, element: string }[],
        sessionTranscript: any
    ): Promise<Uint8Array>;
}
