import { describe, it, expect, vi } from 'vitest';
import { SDJWTStatusResolver } from './status-resolver';

describe('SDJWTStatusResolver', () => {
    it('should correctly map SD-JWT VC status to StatusList2021 entry and check it', async () => {
        // Mock bitstring for index 42 revoked
        // 42nd bit (0-indexed) is in 6th byte (42 // 8 = 5)
        // bit position in byte is 42 % 8 = 2 (if big-endian)
        const bitstring = new Uint8Array(64);
        bitstring[5] = 0b00100000; // Bit 42 set (simplified assumption)

        // Mock StatusListCredential
        const mockSL = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: 'https://example.com/status/1',
            type: ['VerifiableCredential', 'StatusList2021Credential'],
            issuer: 'did:web:issuer.example.com',
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
                id: 'https://example.com/status/1#list',
                type: 'StatusList2021',
                statusPurpose: 'revocation',
                encodedList: Buffer.from(bitstring).toString('base64'),
            }
        };

        const fetchFn = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockSL
        });

        const resolver = new SDJWTStatusResolver({ fetchFn: fetchFn as any });

        // Case 1: Index 42 (revoked in mock)
        const result1 = await resolver.checkStatus({
            status_list: { idx: 42, uri: 'https://example.com/status/1' }
        });

        expect(result1.revoked).toBe(true);
        expect(result1.decision).toBe('DENY');

        // Case 2: Index 10 (not revoked)
        const result2 = await resolver.checkStatus({
            status_list: { idx: 10, uri: 'https://example.com/status/1' }
        });

        expect(result2.revoked).toBe(false);
        expect(result2.decision).toBe('ALLOW');
    });

    it('should fail-closed on fetch failure for high-risk', async () => {
        const fetchFn = vi.fn().mockRejectedValue(new Error('Network error'));
        const resolver = new SDJWTStatusResolver({ fetchFn: fetchFn as any });

        const result = await resolver.checkStatus({
            status_list: { idx: 42, uri: 'https://example.com/status/1' }
        }, 'high');

        expect(result.decision).toBe('DENY');
        expect(result.denyCode).toBe('DENY_STATUS_SOURCE_UNAVAILABLE');
    });
});
