/**
 * Consent Receipts — GDPR Art. 7 demonstrability
 * 
 * Every consent decision produces a signed receipt.
 * Stored locally in the wallet.
 * User can export for complaints/legal proceedings.
 * NO raw PII — only what TYPE of thing was shared.
 */

import { createHash, randomBytes } from "crypto";

// ─── Types ───────────────────────────────────────────────────────

export type ConsentAction = "approved" | "declined" | "partial";

export interface ConsentClaimRecord {
  name: string;                    // "over_18"
  tier: "legal" | "service" | "optional";
  disclosed: boolean;
}

export interface ConsentReceipt {
  id: string;
  version: "v0";
  action: ConsentAction;
  
  verifier: {
    id: string;                    // "coolshop.at"
    name: string;                  // "CoolShop"
    policyRef: string;             // hash of their registered policy
  };
  
  claims: ConsentClaimRecord[];
  
  timestamp: number;
  timestampHuman: string;
  
  evidence: {
    requestHash: string;           // hash of VerificationRequest
    responseHash: string;          // hash of what was sent
    nonce: string;
  };
  
  consent: {
    remembered: boolean;
    expiresAt?: number;
    revokedAt?: number;
  };
}

// ─── Receipt Creation ────────────────────────────────────────────

export interface CreateReceiptInput {
  action: ConsentAction;
  verifierId: string;
  verifierName: string;
  verifierPolicyHash: string;
  claims: ConsentClaimRecord[];
  requestHash: string;
  responseHash: string;
  nonce: string;
  remembered?: boolean;
  rememberUntil?: number;
}

export function createConsentReceipt(input: CreateReceiptInput): ConsentReceipt {
  const now = Date.now();
  return {
    id: `receipt-${randomBytes(8).toString("hex")}`,
    version: "v0",
    action: input.action,
    verifier: {
      id: input.verifierId,
      name: input.verifierName,
      policyRef: input.verifierPolicyHash,
    },
    claims: input.claims,
    timestamp: now,
    timestampHuman: new Date(now).toISOString(),
    evidence: {
      requestHash: input.requestHash,
      responseHash: input.responseHash,
      nonce: input.nonce,
    },
    consent: {
      remembered: input.remembered ?? false,
      expiresAt: input.rememberUntil,
    },
  };
}

// ─── Receipt Store (Local Wallet Storage) ────────────────────────

export class ConsentReceiptStore {
  private receipts: ConsentReceipt[] = [];

  add(receipt: ConsentReceipt): void {
    this.receipts.push(receipt);
  }

  getAll(): ConsentReceipt[] {
    return [...this.receipts];
  }

  getByVerifier(verifierId: string): ConsentReceipt[] {
    return this.receipts.filter(r => r.verifier.id === verifierId);
  }

  revoke(receiptId: string): boolean {
    const receipt = this.receipts.find(r => r.id === receiptId);
    if (!receipt) return false;
    receipt.consent.revokedAt = Date.now();
    return true;
  }

  getSummary(): {
    total: number;
    approved: number;
    declined: number;
    partial: number;
    uniqueVerifiers: number;
  } {
    const verifiers = new Set(this.receipts.map(r => r.verifier.id));
    return {
      total: this.receipts.length,
      approved: this.receipts.filter(r => r.action === "approved").length,
      declined: this.receipts.filter(r => r.action === "declined").length,
      partial: this.receipts.filter(r => r.action === "partial").length,
      uniqueVerifiers: verifiers.size,
    };
  }

  /**
   * Export all receipts (GDPR Art. 20 portability).
   */
  export(): object {
    return {
      format: "mitch-consent-receipts-v0",
      exportedAt: new Date().toISOString(),
      summary: this.getSummary(),
      receipts: this.receipts,
    };
  }
}
