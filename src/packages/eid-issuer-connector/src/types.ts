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
  verificationMethod: 'ausweisapp2' | 'eidas-node' | 'manual' | 'simulator';
}

export interface AusweisApp2Config {
  apiUrl: string; // e.g., 'http://localhost:24727'
  tcTokenUrl: string;
  refreshUrl: string;
}

// ─── Simulator Types ────────────────────────────────────────────────────────

/**
 * Simulated eID-Client protocol states.
 * Models the real AusweisApp2 workflow without actual hardware.
 */
export type EIDProtocolState =
  | 'idle'
  | 'tc_token_generated'
  | 'pin_requested'
  | 'pin_entered'
  | 'card_reading'
  | 'card_read_complete'
  | 'credential_issuing'
  | 'complete'
  | 'error';

export interface EIDProtocolSession {
  sessionId: string;
  state: EIDProtocolState;
  request: EIDIssuanceRequest;
  /** Simulated citizen data (would come from eID chip in production) */
  citizenData?: Record<string, string>;
  createdAt: number;
  completedAt?: number;
  error?: string;
}

/**
 * SD-JWT VC payload structure per SD-JWT-VC spec (draft-ietf-oauth-sd-jwt-vc)
 */
export interface SDJWTVCPayload {
  /** Issuer DID */
  iss: string;
  /** Subject DID */
  sub: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Expiry (Unix timestamp) */
  exp: number;
  /** JWT ID */
  jti: string;
  /** Credential type */
  vct: string;
  /** Status endpoint (optional) */
  status?: { idx: number; uri: string };
  /** Selectively-disclosable claims hashed via _sd */
  _sd?: string[];
  /** Hash algorithm for SD claims */
  _sd_alg?: string;
  /** Non-disclosable claims appear directly */
  [key: string]: unknown;
}

/**
 * Simulator configuration
 */
export interface EIDSimulatorConfig {
  /** DID for the simulated issuer (did:web recommended) */
  issuerDID: string;
  /** Simulated processing delay in ms (default: 0 for tests, 500 for demo) */
  simulatedDelayMs?: number;
  /** Credential validity duration in seconds (default: 365 days) */
  credentialValiditySec?: number;
}

/**
 * DID Document for the simulator's published identity
 */
export interface SimulatorDIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyJwk: Record<string, unknown>;
  }>;
  assertionMethod: string[];
  authentication: string[];
}
