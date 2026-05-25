/**
 * @package @mitch/revocation-statuslist
 * @description Type definitions for StatusList2021 revocation
 */

export interface StatusListCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id: string;
    type: 'StatusList2021';
    statusPurpose: 'revocation' | 'suspension';
    encodedList: string; // Base64-encoded bitstring
  };
}

export interface StatusListEntry {
  id: string; // Status list URL
  type: 'StatusList2021Entry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string; // Index in bitstring
  statusListCredential: string; // URL to StatusListCredential
}

export type RevocationDecision = 'ALLOW' | 'DENY';

export interface RevocationCheckResult {
  decision: RevocationDecision;
  revoked: boolean;
  reason?: string;
  denyCode?: string;
  checkedAt: number;
  listUrl?: string;
  fromCache?: boolean;
  graceMode?: boolean;
}

export interface StatusListCache {
  url: string;
  credential: StatusListCredential;
  fetchedAt: number;
  expiresAt: number;
}

/**
 * Risk tier determines offline grace period behavior.
 * - 'high': no grace period — fail-closed immediately (Layer 1+)
 * - 'low': configurable grace period with cached data
 */
export type RiskTier = 'high' | 'low';

export interface StatusListResolverOptions {
  /** Cache TTL in milliseconds (default: 5 minutes) */
  cacheTtlMs?: number;
  /** Fetch timeout in milliseconds (default: 10 seconds) */
  fetchTimeoutMs?: number;
  /** Offline grace period for low-risk in ms (default: 1 hour). High-risk is always 0. */
  offlineGraceMsLowRisk?: number;
  /** Custom fetch function (for testing) */
  fetchFn?: typeof fetch;
}
