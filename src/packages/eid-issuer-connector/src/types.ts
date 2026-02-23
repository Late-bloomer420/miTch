/**
 * @package @mitch/eid-issuer-connector
 * @description Types for German eID issuer integration
 */

export interface EIDIssuanceRequest {
  userDID: string;
  requestedAttributes: string[]; // e.g., ['givenName', 'familyName', 'dateOfBirth']
  purpose: string; // Purpose for GDPR Art. 6
}

export interface EIDIssuanceResponse {
  credential: string; // JWT or SD-JWT
  format: 'jwt' | 'sd-jwt-vc';
  issuer: string; // Issuer DID
  issuedAt: number;
  expiresAt: number;
}

export interface EIDAttribute {
  name: string;
  value: string;
  verified: boolean; // True if from official eID
  verificationMethod: 'ausweisapp2' | 'eidas-node' | 'manual';
}

export interface AusweisApp2Config {
  apiUrl: string; // e.g., 'http://localhost:24727'
  tcTokenUrl: string;
  refreshUrl: string;
}
