import { describe, expect, it } from 'vitest';
import { isIssuerTrustedFor } from '../utils/issuer-trust';

const gov = { did: 'did:example:gov-issuer', name: 'Gov', credentialTypes: ['AgeCredential'] };

describe('isIssuerTrustedFor', () => {
  it('trusts an issuer listed for one of the credential types', () => {
    expect(
      isIssuerTrustedFor([gov], 'did:example:gov-issuer', ['VerifiableCredential', 'AgeCredential'])
    ).toBe(true);
  });

  it('does not trust an unlisted issuer', () => {
    expect(isIssuerTrustedFor([gov], 'did:askmi:self', ['AgeCredential'])).toBe(false);
  });

  it('does not trust a listed issuer for a type it is not listed for', () => {
    expect(isIssuerTrustedFor([gov], 'did:example:gov-issuer', ['Prescription'])).toBe(false);
  });

  it('does not trust an entry whose validUntil has passed', () => {
    const expired = { ...gov, validUntil: '2020-01-01T00:00:00Z' };
    const now = new Date('2026-10-25T00:00:00Z');
    expect(isIssuerTrustedFor([expired], gov.did, ['AgeCredential'], now)).toBe(false);
  });

  it('does not trust an entry with an unreadable validUntil (fail closed)', () => {
    const broken = { ...gov, validUntil: 'not-a-date' };
    expect(isIssuerTrustedFor([broken], gov.did, ['AgeCredential'])).toBe(false);
  });

  it('does not trust anything when there is no trust list', () => {
    expect(isIssuerTrustedFor(undefined, gov.did, ['AgeCredential'])).toBe(false);
  });
});
