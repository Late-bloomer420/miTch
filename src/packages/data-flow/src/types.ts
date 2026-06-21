import type { AuditEventType, IdentityFirewallMetadata } from '@askmi/shared-types';

export type IdentityFirewallAccess = Omit<IdentityFirewallMetadata, 'decision_id'>;

export interface DataFlowTransaction {
  transactionId: string;
  startedAt: string;
  completedAt: string | null;
  verifierId: string | null;
  verifierLabel: string;
  /**
   * Policy verdict for this transaction (G-140 PR2). Present when a disclosure
   * decision event (POLICY_EVALUATED) was logged — including DENY transactions
   * that never produced a VP_GENERATED. Optional for backward compatibility.
   */
  verdict?: 'ALLOW' | 'DENY' | 'PROMPT';
  claimsShared: string[];
  claimsRequested: string[] | null;
  claimsWithheld: string[] | null;
  provenClaims: string[];
  credentialTypes: string[];
  usedZKP: boolean;
  /**
   * True iff this presentation consumed a batch-issued single-use credential
   * member (Proof-Randomization U-12, see SPRINT_PROOF_RANDOMIZATION.md).
   * Optional for backward compatibility with legacy transactions / fixtures
   * predating Sprint Proof-Randomization.
   */
  singleUseCredential?: boolean;
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
