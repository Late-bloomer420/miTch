import { describe, it, expect } from 'vitest';
import { OID4VCIIssuer } from '../src/index';
import { BatchCredentialRequest } from '../src/types';

describe('OID4VCI Batch Issuance (§7)', () => {
    const mockDid = 'did:askmi:issuer-test';
    const mockKey = { kty: 'OKP', crv: 'Ed25519', x: 'mock', d: 'mock' } as JsonWebKey;
    const issuer = new OID4VCIIssuer(mockDid, mockKey);

    const validCredentialRequest = {
        credential_type: 'IdentityCredential' as const,
        subject_did: 'did:key:user123',
        claims: {
            name: 'Alice',
            birthDate: '2000-01-01',
            residency: 'DE'
        },
        nonce: 'nonce-12345678'
    };

    it('should issue multiple credentials in a single batch', async () => {
        const batchRequest: BatchCredentialRequest = {
            credential_requests: [
                validCredentialRequest,
                { ...validCredentialRequest, nonce: 'nonce-87654321' }
            ]
        };

        const response = await issuer.issueBatchCredential(batchRequest);
        
        expect(response.credential_responses).toHaveLength(2);
        expect(response.credential_responses[0].credential).toContain('mock_signature');
        expect(response.credential_responses[1].credential).toContain('mock_signature');
        expect(response.c_nonce).toBeDefined();
    });

    it('should FAIL_CLOSED the entire batch if one request is invalid', async () => {
        const batchRequest = {
            credential_requests: [
                validCredentialRequest,
                { ...validCredentialRequest, credential_type: 'InvalidType' } // This will fail validation
            ]
        };

        // Note: issueBatchCredential will first validate the batch schema via BatchCredentialRequestSchema
        // The nested CredentialRequestSchema will catch the 'InvalidType' violation.
        await expect(issuer.issueBatchCredential(batchRequest))
            .rejects
            .toThrow(/FAIL_INPUT_ARBITRATION/);
    });

    it('should enforce atomicity (reproducibility)', async () => {
        const batchRequest: BatchCredentialRequest = {
            credential_requests: [
                validCredentialRequest,
                { ...validCredentialRequest, subject_did: 'did:evil' } // This will fail the validateIssuancePolicy check
            ]
        };

        await expect(issuer.issueBatchCredential(batchRequest))
            .rejects
            .toThrow(/FAIL_POLICY: Subject blocked/);
    });
});
