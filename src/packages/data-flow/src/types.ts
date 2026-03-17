export interface DataFlowTransaction {
  transactionId: string;
  startedAt: string;
  completedAt: string | null;
  verifierId: string | null;
  verifierLabel: string;
  claimsShared: string[];
  claimsRequested: string[] | null;
  claimsWithheld: string[] | null;
  provenClaims: string[];
  credentialTypes: string[];
  usedZKP: boolean;
  lifecycle: {
    keysCreated: number;
    keysDestroyed: number;
    fullyShredded: boolean;
    shreddingLatencyMs: number | null;
  };
  events: DataFlowEvent[];
}

export interface DataFlowEvent {
  auditEntryId: string;
  timestamp: string;
  label: string;
  category: 'key' | 'credential' | 'presentation' | 'policy' | 'consent';
  detail?: string;
}
