import { describe, it, expect, beforeEach } from 'vitest';
import { EIDIssuerConnector } from '../index';
import type { EIDIssuanceRequest } from '../types';

describe('EIDIssuerConnector', () => {
  let connector: EIDIssuerConnector;

  beforeEach(async () => {
    connector = new EIDIssuerConnector('mock');
    await connector.initialize();
  });

  it('should create connector in mock mode', () => {
    expect(connector).toBeDefined();
  });

  it('should issue mock credential', async () => {
    const request: EIDIssuanceRequest = {
      userDID: 'did:example:alice',
      requestedAttributes: ['givenName', 'familyName', 'dateOfBirth'],
      purpose: 'Age verification for online service',
    };

    const response = await connector.requestIssuance(request);

    expect(response.credential).toBeDefined();
    expect(response.format).toBe('jwt');
    expect(response.issuer).toBe('did:example:german-government');
    expect(response.expiresAt).toBeGreaterThan(Date.now());
  });

  it('should throw error for unimplemented modes', async () => {
    const ausweisConnector = new EIDIssuerConnector('ausweisapp2');
    await expect(ausweisConnector.initialize()).rejects.toThrow('not yet implemented');
  });
});
