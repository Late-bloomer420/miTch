import type { DataFlowTransaction } from './types';

/**
 * Plain-language summary of what miTch did for the user in a transaction.
 * Derived purely from existing DataFlowTransaction fields — no speculation.
 */
export interface TransactionSummary {
  /** Individual summary points (each a self-contained statement) */
  points: string[];
}

/**
 * Generate a plain-language summary of a transaction's privacy properties.
 *
 * All statements are derived from auditable data already in DataFlowTransaction.
 * No speculation, no risk scoring — just facts the user can verify.
 */
export function summarizeTransaction(txn: DataFlowTransaction): TransactionSummary {
  const points: string[] = [];

  // 1. ZKP usage — predicate proofs instead of raw disclosure
  if (txn.usedZKP && txn.provenClaims.length > 0) {
    if (txn.provenClaims.length === 1) {
      points.push(`${txn.provenClaims[0]} bewiesen statt offengelegt`);
    } else {
      points.push(`${txn.provenClaims.length} Eigenschaften bewiesen statt offengelegt`);
    }
  }

  // 2. Claims withheld — what was blocked
  if (txn.claimsWithheld !== null && txn.claimsWithheld.length > 0) {
    if (txn.claimsWithheld.length === 1) {
      points.push(`${txn.claimsWithheld[0]} zurückgehalten`);
    } else {
      points.push(`${txn.claimsWithheld.length} Claims zurückgehalten`);
    }
  }

  // 3. Crypto-shredding status
  if (txn.lifecycle.fullyShredded) {
    if (txn.lifecycle.shreddingLatencyMs !== null) {
      const seconds = (txn.lifecycle.shreddingLatencyMs / 1000).toFixed(1);
      points.push(`Daten vergessen nach ${seconds}s`);
    } else {
      points.push('Daten vergessen');
    }
  } else if (txn.lifecycle.keysCreated > 0) {
    const open = txn.lifecycle.keysCreated - txn.lifecycle.keysDestroyed;
    points.push(`${open} Schlüssel noch aktiv`);
  }

  // 4. Minimal disclosure — nothing shared beyond proofs
  if (txn.claimsShared.length === 0 && txn.provenClaims.length > 0) {
    points.push('Keine Rohdaten geteilt');
  }

  return { points };
}
