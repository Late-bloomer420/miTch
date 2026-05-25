/**
 * Canonical consent receipt contracts shared across wallet, protocol demos,
 * and export tooling. Receipts intentionally contain metadata only, never raw
 * credential values.
 */

export type ConsentReceiptOutcome = 'SUCCESS' | 'DENIED' | 'ERROR';

export interface ConsentReceiptV1 {
  schemaVersion: 1;
  id: string;
  verifier: string;
  purpose: string;
  claimsShared: string[];
  timestamp: string;
  outcome: ConsentReceiptOutcome;
  decisionId: string | null;
}

export type ConsentReceipt = ConsentReceiptV1;

export type ConsentReceiptExportScope = 'filtered' | 'full';

export interface ConsentReceiptExportFilters {
  verifierQuery: string;
  timeframe: 'all' | '24h' | '7d' | '30d';
}

export interface ConsentReceiptExportV1 {
  exportedAt: string;
  scope: ConsentReceiptExportScope;
  filters: ConsentReceiptExportFilters;
  count: number;
  auditAnchorHash: string | null;
  receiptSetHash: string;
  exportHash: string;
  receipts: ConsentReceiptV1[];
}

export type ConsentReceiptExport = ConsentReceiptExportV1;
