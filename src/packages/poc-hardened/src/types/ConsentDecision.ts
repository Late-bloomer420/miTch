/**
 * ConsentDecision - Binary decision from policy engine
 * 
 * CONSTRAINT: Decision is YES or NO. Never a data value.
 * External systems never see the reason (audit only).
 */
export interface ConsentDecision {
  /** Links back to the original AccessRequest */
  requestId: string;

  /** Whether policy allows this access */
  allowed: boolean;

  /** Why this decision was made (for user audit, not external systems) */
  reason: string;

  /** Optional constraints on how this decision can be used */
  constraints?: {
    /** When this decision expires (Unix timestamp) - revocable */
    validUntil?: number;

    /** Whether this decision appears in user's audit log */
    auditLog: boolean;
  };

  /** When this decision was made */
  decidedAt: number;
}
