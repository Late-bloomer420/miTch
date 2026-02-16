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

export interface RevocationCheckResult {
  revoked: boolean;
  reason?: 'REVOKED' | 'SUSPENDED' | 'LIST_UNAVAILABLE' | 'INVALID_INDEX';
  checkedAt: number;
  listUrl?: string;
}

export interface StatusListCache {
  url: string;
  credential: StatusListCredential;
  fetchedAt: number;
  expiresAt: number;
}
