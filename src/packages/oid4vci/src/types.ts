import { z } from 'zod';

// ----------------------------------------------------------------------------
// FAILURE MODES (Reason Codes) implemented as Type constraints
// ----------------------------------------------------------------------------

/**
 * A verifiable credential request.
 * 
 * PRIVACY CHECK:
 * - Data Minimization: Only strictly necessary fields.
 * - Purpose Limitation: Bound to 'credential_issuance'.
 */
export const CredentialRequestSchema = z.object({
    credential_type: z.literal('IdentityCredential'),

    // The subject Did to bind the credential to
    subject_did: z.string().startsWith('did:'),

    claims: z.object({
        name: z.string()
            .describe('Art. 6(1)(b) - Required for identity binding'),

        birthDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/)
            .describe('Art. 6(1)(b) - Required for age verification capability'),

        residency: z.string().length(2)
            .describe('Art. 6(1)(b) - Required for jurisdiction check')
    }),

    // Replay protection
    nonce: z.string().min(8),

    // Binding to the specific offer
    issuer_state: z.string().optional()
});

export type CredentialRequest = z.infer<typeof CredentialRequestSchema>;

/**
 * The response containing the crypto-bound credential.
 * 
 * SECURITY CHECK:
 * - Structural Non-Existence: No user data in response body (only in VC)
 */
export const CredentialResponseSchema = z.object({
    credential: z.string()
        .describe('JWS/JWT signed Verifiable Credential'),

    c_nonce: z.string().optional(),
    c_nonce_expires_in: z.number().optional()
});

export type CredentialResponse = z.infer<typeof CredentialResponseSchema>;
