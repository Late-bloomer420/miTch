export type ConsentReceiptOutcome = 'SUCCESS' | 'DENIED' | 'ERROR';

export interface ConsentReceipt {
  schemaVersion: 1;
  id: string;
  verifier: string;
  purpose: string;
  claimsShared: string[];
  timestamp: string;
  outcome: ConsentReceiptOutcome;
  decisionId: string | null;
}
