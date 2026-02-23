/**
 * AccessRequest - External system requests access to user data
 * 
 * CONSTRAINT: Specifies WHAT and WHY, never HOW.
 * The vault never receives this. Policy engine uses it to decide.
 */
export interface AccessRequest {
  /** Unique identifier for this request (for audit trail) */
  requestId: string;

  /** System user identifier - NOT PII */
  userId: string;

  /** Data categories being requested (e.g., "age_verification", "email_proof") */
  dataCategories: string[];

  /** Purpose of access - human readable (e.g., "age_gate", "account_recovery") */
  purpose: string;

  /** Unix timestamp when request was made */
  timestamp: number;
}
