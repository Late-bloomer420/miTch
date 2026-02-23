/**
 * ROPA — Records of Processing Activities (GDPR Art. 30)
 * 
 * Aggregate-only processing records.
 * Tracks WHAT categories of processing happened, not WHO.
 * Required for any data controller deploying miTch.
 */

// ─── Types ───────────────────────────────────────────────────────

export interface ProcessingActivity {
  activity: string;               // "credential_issuance" | "age_verification" | ...
  controller: {
    entity: string;               // "CoolShop GmbH"
    purpose: string;              // "Age verification for alcohol sales"
    legalBasis: string;           // "JuSchG §2" or "GDPR Art. 6(1)(a)"
  };
  dataCategories: string[];       // ["age_predicate"] — never raw PII categories
  recipientCategories: string[];  // ["verifier_merchant"]
  retentionPolicy: string;        // "crypto_shredded_after_transaction"
  safeguards: string[];           // ["selective_disclosure", "crypto_shredding", "response_padding"]
}

export interface ROPAEntry {
  period: string;                 // "2026-02" (monthly)
  activity: string;
  controller: string;
  count: number;                  // aggregate count
  dataCategories: string[];
  legalBasis: string;
}

// ─── ROPA Store ──────────────────────────────────────────────────

export class ROPAStore {
  private entries: Map<string, ROPAEntry> = new Map();
  private activities: Map<string, ProcessingActivity> = new Map();

  /**
   * Register a processing activity (done once per activity type).
   */
  registerActivity(activity: ProcessingActivity): void {
    this.activities.set(activity.activity, activity);
  }

  /**
   * Record that a processing activity occurred.
   * Only increments a counter — no PII, no per-request details.
   */
  record(activityName: string, controllerEntity?: string): void {
    const activity = this.activities.get(activityName);
    if (!activity) return;

    const now = new Date();
    const period = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
    const key = `${period}:${activityName}:${controllerEntity ?? activity.controller.entity}`;

    const existing = this.entries.get(key);
    if (existing) {
      existing.count++;
    } else {
      this.entries.set(key, {
        period,
        activity: activityName,
        controller: controllerEntity ?? activity.controller.entity,
        count: 1,
        dataCategories: activity.dataCategories,
        legalBasis: activity.controller.legalBasis,
      });
    }
  }

  /**
   * Get all ROPA entries (for compliance report).
   */
  getEntries(): ROPAEntry[] {
    return Array.from(this.entries.values());
  }

  /**
   * Get registered activity definitions.
   */
  getActivities(): ProcessingActivity[] {
    return Array.from(this.activities.values());
  }

  /**
   * Export ROPA as structured report.
   */
  export(): object {
    return {
      title: "Records of Processing Activities (GDPR Art. 30)",
      generatedAt: new Date().toISOString(),
      activities: this.getActivities(),
      aggregateRecords: this.getEntries(),
      note: "All records are aggregate counts. No personal data is stored in this log.",
    };
  }
}
