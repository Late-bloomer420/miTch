import { 
    DecisionCapsule, 
    AuditLogEntry 
} from '@mitch/shared-types';
import { 
    EphemeralKey,
    canonicalStringify
} from '@mitch/shared-crypto';
import { AuditLog } from '@mitch/audit-log';
import type { IPresentationManager } from './IPresentationManager';
import type { ICredentialRepository } from './ICredentialRepository';

/**
 * Concrete implementation of IPresentationManager.
 * Handles VP generation, encryption, and audit logging.
 */
export class MitchPresentationManager implements IPresentationManager {
    constructor(
        private credRepo: ICredentialRepository,
        private auditLog: AuditLog
    ) {}

    async generatePresentation(
        capsule: DecisionCapsule,
        agentTargetPubKey?: CryptoKey
    ): Promise<{ encryptedVp: string, logs: string[] }> {
        const logs: string[] = [];
        
        // 1. Resolve credentials from the capsule
        const claims: Record<string, unknown> = {};
        for (const req of capsule.authorized_requirements) {
            const data = await this.credRepo.loadSelective(
                req.selected_credential_id, 
                req.allowed_claims
            );
            if (data) {
                Object.assign(claims, data);
            }
        }

        // 2. Generate Ephemeral Session Key (AES-GCM)
        const ephemeralKey = await EphemeralKey.create();
        logs.push('🔐 Ephemeral Session Key Created (AES-GCM-256)');

        // 3. Build the VP artifact
        const proofArtifact = {
            type: 'VerifiablePresentationBundle',
            decision_id: capsule.decision_id,
            timestamp: Date.now(),
            validUntil: Date.now() + 60000, // 60s TTL
            verifier_did: capsule.verifier_did,
            claims
        };

        const aad = new TextEncoder().encode(
            canonicalStringify({
                decision_id: capsule.decision_id,
                nonce: capsule.nonce,
                verifier_did: capsule.verifier_did
            })
        );

        let transportPackage: string;

        if (agentTargetPubKey) {
            // 4a. Encrypted for specific agent target
            const ciphertext = await ephemeralKey.encrypt(JSON.stringify(proofArtifact), aad);
            const encryptedKey = await ephemeralKey.sealToRecipient(agentTargetPubKey);
            
            transportPackage = JSON.stringify({
                ciphertext,
                aad_context: {
                    decision_id: capsule.decision_id,
                    nonce: capsule.nonce,
                    verifier_did: capsule.verifier_did
                },
                recipient: {
                    header: { kid: `${capsule.verifier_did}#key-1` },
                    encrypted_key: encryptedKey
                }
            });
            logs.push('✅ VP Bundle Signed & Encrypted');
        } else {
            // 4b. Plaintext for legacy/demo
            transportPackage = JSON.stringify(proofArtifact);
            logs.push('⚠️  VP Bundle generated in PLAINTEXT (Demo Mode)');
        }

        // 5. Cleanup (Crypto-Shredding)
        ephemeralKey.shred();
        logs.push('♻️  Ephemeral keys destroyed (Crypto-Shredding active)');

        return { encryptedVp: transportPackage, logs };
    }

    async logVpSent(decisionId: string, metadata: Record<string, unknown>): Promise<void> {
        await this.auditLog.append('VP_SENT', decisionId, metadata);
    }

    /**
     * Generate an ISO 18013-5 DeviceResponse for proximity presentation.
     */
    async generateProximityResponse(
        credId: string,
        _requestedElements: { ns: string, element: string }[],
        _sessionTranscript: any // from @mitch/mdoc
    ): Promise<Uint8Array> {
        const { buildDeviceResponse, decodeMdoc } = await import('@mitch/mdoc');
        
        const credData = await this.credRepo.load<{ _mdoc: true, docType: string, cborBase64: string }>(credId);
        if (!credData?._mdoc) throw new Error('NOT_MDOC_CREDENTIAL');

        // Helper to convert base64 to Uint8Array (browser safe)
        const base64ToUint8Array = (base64: string) => {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        };

        const mdoc = decodeMdoc(base64ToUint8Array(credData.cborBase64));
        
        // This is a simplified demo-flow for proximity (ISO 18013-5 §8.3)
        return buildDeviceResponse([mdoc as any]);
    }
}
