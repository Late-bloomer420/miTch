/**
 * Proof - Minimal proof to send to external systems
 * 
 * CONSTRAINT: Contains NO raw data. Only attestation of validity.
 * Example: { isValid: true, proofType: "age_over_18" } - not "age: 27"
 */
export interface Proof {
  /** Links back to the AccessRequest this proves */
  requestId: string;

  /** The only substantive claim: is the data valid or not? */
  isValid: boolean;

  /** Type of proof (e.g., "age_over_18", "email_verified") */
  proofType: string;

  /** When this proof was generated */
  generatedAt: number;

  /** When this proof expires (Unix timestamp) */
  expiresAt?: number;

  /** Placeholder for future cryptographic signature */
  signature?: string;
}
