/**
 * Geographic Scope helpers for EHDS compliance (T-A4).
 * Determines whether a verifier's country is permitted under a policy rule's geoScope.
 */

export const EU_EEA_COUNTRIES = new Set([
  'AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE',
  'IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE',
  'IS','LI','NO'
]);

export const ADEQUACY_COUNTRIES = new Set([
  'AD','AR','CA','FO','GG','IL','IM','JP','JE','NZ','KR','CH','UY','UK'
]);

export function isAllowedByGeoScope(geoScope: string, countryCode: string | null): boolean {
  if (!countryCode) return true; // Can't determine → allow (fail-open for geo only)
  if (geoScope === 'global') return true;
  const upper = countryCode.toUpperCase();
  if (geoScope === 'eu-only') return EU_EEA_COUNTRIES.has(upper);
  if (geoScope === 'eu-plus-adequacy') return EU_EEA_COUNTRIES.has(upper) || ADEQUACY_COUNTRIES.has(upper);
  return true;
}

export function extractCountryFromDid(did: string): string | null {
  // Format: did:XX:name → XX is country code (2 letters)
  const parts = did.split(':');
  if (parts.length >= 3 && parts[1].length === 2) return parts[1].toUpperCase();
  return null;
}
