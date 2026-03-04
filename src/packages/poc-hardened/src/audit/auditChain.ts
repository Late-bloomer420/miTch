/**
 * Audit Chain — Tamper-evident hash chain for all miTch actions
 * 
 * Every action (issue, present, consent, shred) gets an entry.
 * Entries are hash-chained: tampering with one breaks the chain.
 * NO PII stored — only hashes, categories, and timestamps.
 */

import { createHash, randomBytes } from "crypto";

// ─── Types ───────────────────────────────────────────────────────

export type AuditAction = 
  | "credential_issued"
  | "credential_presented"
  | "credential_revoked"
  | "credential_unrevoked"
  | "consent_given"
  | "consent_revoked"
  | "crypto_shred"
  | "verification_denied"
  | "verification_allowed";

export interface ShredProof {
  keyId: string;
  algorithm: string;
  destroyedAt: string;
  method: "key_zeroed" | "key_overwrite" | "key_deleted";
}

export interface AuditEvidence {
  credentialHash?: string;
  disclosureHash?: string;
  consentHash?: string;
  shredProof?: ShredProof;
  verifierIdHash?: string;
  claimCategories?: string[];
  decisionCode?: string;
}

export interface AuditEntry {
  id: string;
  sequence: number;
  previousHash: string;
  entryHash: string;
  action: AuditAction;
  evidence: AuditEvidence;
  timestamp: string;           // ISO string, full precision for audit
  timestampCoarse: string;     // "2026-02" — for ROPA aggregation
}

// ─── Chain Implementation ────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha-256").update(data, "utf8").digest("hex");
}

function computeEntryHash(entry: Omit<AuditEntry, "entryHash">): string {
  const canonical = JSON.stringify({
    id: entry.id,
    sequence: entry.sequence,
    previousHash: entry.previousHash,
    action: entry.action,
    evidence: entry.evidence,
    timestamp: entry.timestamp,
  });
  return sha256(canonical);
}

export class AuditChain {
  private entries: AuditEntry[] = [];
  private lastHash: string = "GENESIS";

  /**
   * Append an action to the audit chain.
   * Returns the new entry (with hash).
   */
  append(action: AuditAction, evidence: AuditEvidence): AuditEntry {
    const now = new Date();
    const id = `audit-${randomBytes(8).toString("hex")}`;
    const sequence = this.entries.length;

    const partial: Omit<AuditEntry, "entryHash"> = {
      id,
      sequence,
      previousHash: this.lastHash,
      action,
      evidence,
      timestamp: now.toISOString(),
      timestampCoarse: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`,
    };

    const entryHash = computeEntryHash(partial);
    const entry: AuditEntry = { ...partial, entryHash };

    this.entries.push(entry);
    this.lastHash = entryHash;

    return entry;
  }

  /**
   * Verify the entire chain is intact (no tampering).
   */
  verify(): { valid: boolean; brokenAt?: number; reason?: string } {
    let expectedPrevious = "GENESIS";

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // Check previous hash link
      if (entry.previousHash !== expectedPrevious) {
        return { valid: false, brokenAt: i, reason: "previous_hash_mismatch" };
      }

      // Check entry hash
      const { entryHash, ...rest } = entry;
      const computed = computeEntryHash(rest as Omit<AuditEntry, "entryHash">);
      if (computed !== entryHash) {
        return { valid: false, brokenAt: i, reason: "entry_hash_mismatch" };
      }

      expectedPrevious = entryHash;
    }

    return { valid: true };
  }

  /**
   * Get all entries (for export/display).
   */
  getEntries(): AuditEntry[] {
    return [...this.entries];
  }

  /**
   * Get chain length.
   */
  get length(): number {
    return this.entries.length;
  }

  /**
   * Get the last entry.
   */
  get latest(): AuditEntry | undefined {
    return this.entries[this.entries.length - 1];
  }

  /**
   * Export chain as JSON (for audit report).
   */
  export(): string {
    return JSON.stringify({
      chainLength: this.entries.length,
      genesisHash: "GENESIS",
      latestHash: this.lastHash,
      verified: this.verify().valid,
      entries: this.entries,
    }, null, 2);
  }
}
