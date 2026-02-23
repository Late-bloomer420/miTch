export type KeyStatus = "active" | "revoked" | "missing" | "unavailable" | "resolver_quorum_failed";

export interface ResolvedKey {
  status: KeyStatus;
  publicKeyPem?: string;
}

export type ResolveKey = (keyId?: string) => Promise<ResolvedKey>;
