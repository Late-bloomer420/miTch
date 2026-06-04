import type { AuditEventType, IdentityFirewallMetadata } from '@askmi/shared-types';

export type IdentityFirewallAccess = Omit<IdentityFirewallMetadata, 'decision_id'>;

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
  identityAccesses: IdentityFirewallAccess[];
  identityAccessCount: number;
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
  action: AuditEventType;
  label: string;
  category: 'key' | 'credential' | 'presentation' | 'policy' | 'consent' | 'identity';
  detail?: string;
  metadata?: Record<string, unknown>;
}
