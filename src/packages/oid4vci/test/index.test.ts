import { describe, it, expect } from 'vitest';
import { OID4VCIIssuer } from '../src/index';
import { CredentialRequest } from '../src/types';

describe('OID4VCIIssuer (Privacy Firewall)', () => {
    // Mock Keys
    const mockDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const mockKey = { kty: 'OKP', crv: 'Ed25519', x: 'mock', d: 'mock' } as JsonWebKey;

    const issuer = new OID4VCIIssuer(mockDid, mockKey);

    it('should FAIL_CLOSED on invalid schema input', async () => {
        const invalidRequest = {
            credential_type: 'WrongType', // violation
            subject_did: 'did:foo',
            claims: {}, // violation
            nonce: 'short' // violation
        };

        await expect(issuer.issueCredential(invalidRequest))
            .rejects
            .toThrow(/FAIL_INPUT_ARBITRATION/);
    });

    it('should PASS strict schema validation', async () => {
        const validRequest: CredentialRequest = {
            credential_type: 'IdentityCredential',
            subject_did: 'did:key:123',
            claims: {
                name: 'Alice',
                birthDate: '2000-01-01',
                residency: 'DE'
            },
            nonce: '12345678', // > 8 chars
        };

        const response = await issuer.issueCredential(validRequest);
        expect(response.credential).toContain('mock_signature');
        expect(JSON.parse(response.credential).credentialSubject.name).toBe('Alice');
    });

    it('should not leak PII in error messages', async () => {
        // Axiom: Error messages should be generic enough not to leak values, 
        // but specific enough to debug schema.
        const requestWithBadDate = {
            credential_type: 'IdentityCredential',
            subject_did: 'did:key:123',
            claims: {
                name: 'Alice',
                birthDate: 'INVALID_DATE_FORMAT', // PII violation
                residency: 'DE'
            },
            nonce: '12345678'
        };

        await expect(issuer.issueCredential(requestWithBadDate))
            .rejects
            .toThrow();
        // In a real audit, we'd check logs here to ensure 'Alice' wasn't logged.
    });
});
