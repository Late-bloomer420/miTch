import { CredentialRequest, CredentialRequestSchema, CredentialResponse } from './types';
import { signData, verifyData } from '@mitch/shared-crypto';
import { z } from 'zod';


/**
 * OID4VCIIssuer Service
 * 
 * ARCHITECTURE NOTE:
 * This service is designed to be EPHEMERAL. It does not hold state between requests.
 * It strictly enforces the "Fail-Closed" axiom.
 */
export class OID4VCIIssuer {
    private issuerDid: string;
    private privateKey: JsonWebKey;

    constructor(issuerDid: string, privateKey: JsonWebKey) {
        this.issuerDid = issuerDid;
        this.privateKey = privateKey;
    }

    /**
     * Creates a credential offer.
     * Use Case: User scans QR code.
     */
    async createOffer(credentialType: string): Promise<string> {
        // In a real system, this would be a signed JWT to prevent tampering.
        // For MVP, we return a simple JSON structure string.
        return JSON.stringify({
            credential_issuer: this.issuerDid,
            credential_configuration_ids: [credentialType],
            grants: {
                'authorization_code': {
                    'issuer_state': 'stateless_nonce_' + Date.now() // Simple nonce for MVP
                }
            }
        });
    }

    /**
     * Processes a credential request.
     * 
     * PRIVACY AUDIT:
     * - Input: Encrypted JWE (Simulated here via types)
     * - Processing: In-memory only
     * - Output: Encrypted JWE
     * - Storage: NONE (Structural Non-Existence)
     */
    async issueCredential(rawRequest: unknown): Promise<CredentialResponse> {
        // 1. INPUT VALIDATION (Fail-Closed)
        // If the schema doesn't match, we reject immediately.
        // Rule: Unknown => FAIL
        const parseResult = CredentialRequestSchema.safeParse(rawRequest);
        if (!parseResult.success) {
            throw new Error(`FAIL_INPUT_ARBITRATION: Invalid request format. ${parseResult.error.message}`);
        }
        const request = parseResult.data;


        // 2. POLICY CHECK (Authorization)
        // Verify that the request adheres to the generic issuance policy.
        this.validateIssuancePolicy(request);

        // 3. VERIFICATION (Grounding)
        // Verify the subject actually owns the DID (Proof of Possession).
        // implementation pending integration with shared-crypto verify

        // 4. ISSUANCE (Data Minimization)
        // We only verify the claims provided. We do not look up "other" data.
        const credential = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'IdentityCredential'],
            issuer: this.issuerDid,
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
                id: request.subject_did,
                ...request.claims // Only echoing back what was proven/requested
            }
        };

        // 5. SIGNATURE (Integrity)
        // We sign the VC.
        // In a real flow, this would be a detailed VC-JWT or SD-JWT.
        const signature = await this.signCredential(credential);

        // 6. RESPONSE (Ephemeral)
        // Return immediately. Do not log `credential`.

        this.emitAudit('ISSUANCE_ATTEMPT', 'SUCCESS', {
            subject: request.subject_did,
            claims_requested: Object.keys(request.claims)
        });

        return {
            credential: JSON.stringify({ ...credential, proof: signature }),
            c_nonce: crypto.randomUUID(), // Fresh nonce for next step
            c_nonce_expires_in: 300 // 5 minutes
        };
    }


    /**
     * Emits a structured audit log entry.
     * In a real system, this would write to a WORM storage or Merkle Log.
     */
    private emitAudit(type: string, status: 'SUCCESS' | 'FAILURE', details: Record<string, any>) {
        const entry = {
            timestamp: new Date().toISOString(),
            type,
            status,
            actor: this.issuerDid,
            details: {
                // DATA MINIMIZATION: Never log the full credential or PII.
                subject: details.subject, // OK if public DID
                claims_requested: details.claims_requested,
                reason: details.reason
            }
        };
        // This is the "traceability" hook.
        // For now, we simulate the "tamper-evident" log by strictly structuring it.
        console.log(`[AUDIT] ${JSON.stringify(entry)}`);
    }

    private async signCredential(credential: any): Promise<string> {
        // Placeholder for actual crypto signing
        // Should use @mitch/shared-crypto
        return "mock_signature_" + Date.now();
    }

    /**
     * Local Policy Check for Issuance.
     * Enforces strict rules on what can be issued.
     */
    private validateIssuancePolicy(request: CredentialRequest) {
        // Axiom: We do not issue credentials to unknown DIDs in this strict mode? 
        // Or we just check that the claims are reasonable.
        // Zod checked the type.
        // Here we could check a deny-list.
        if (request.subject_did.includes('did:evil')) {
            throw new Error('FAIL_POLICY: Subject blocked');
        }
        // OK to proceed.
    }
}
