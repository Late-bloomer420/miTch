import { describe, it, expect, beforeEach } from 'vitest';
import { StatusListRevocationChecker } from '../index';
import type { StatusListEntry, StatusListCredential } from '../types';

describe('StatusListRevocationChecker', () => {
  let checker: StatusListRevocationChecker;

  beforeEach(() => {
    checker = new StatusListRevocationChecker({ cacheMinutes: 1 });
  });

  it('should create checker with default options', () => {
    const defaultChecker = new StatusListRevocationChecker();
    expect(defaultChecker).toBeDefined();
  });

  it('should decode bitstring correctly', async () => {
    // Mock status entry pointing to index 0 (revoked)
    const statusEntry: StatusListEntry = {
      id: 'https://example.com/status/1',
      type: 'StatusList2021Entry',
      statusPurpose: 'revocation',
      statusListIndex: '5',
      statusListCredential: 'https://example.com/status-list/1',
    };

    // Mock bitstring with bit 5 set (revoked)
    // Byte 0: bit 5 = 00100000 = 0x20
    const bitstring = new Uint8Array([0x20]); // Bit 5 is set
    const encoded = btoa(String.fromCharCode(...bitstring));

    // Mock credential
    const mockCredential: StatusListCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'https://example.com/status-list/1',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:example:issuer',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'https://example.com/status-list/1#list',
        type: 'StatusList2021',
        statusPurpose: 'revocation',
        encodedList: encoded,
      },
    };

    // Test: Check index 5 (should be revoked)
    const result = await checker['checkBitstring'](statusEntry, mockCredential);
    expect(result.revoked).toBe(true);
    expect(result.reason).toBe('REVOKED');
  });

  it('should handle cache correctly', () => {
    const stats = checker.getCacheStats();
    expect(stats.size).toBe(0);
    expect(stats.urls).toEqual([]);
  });

  it('should clear cache', () => {
    checker.clearCache();
    expect(checker.getCacheStats().size).toBe(0);
  });
});
