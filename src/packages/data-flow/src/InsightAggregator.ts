import type { AuditLogEntry } from '@askmi/shared-types';
import { DataFlowService } from './service';

const UNKNOWN_CLAIM_VALUE = 0.1;

const CLAIM_VALUE_ESTIMATES: Record<string, number> = {
  name: 0.5,
  dateOfBirth: 1.2,
  birthDate: 1.2,
  age: 0.1,
  email: 2,
  address: 1.5,
  homeAddress: 1.5,
  nationalId: 5,
  healthRecord: 15,
  medicalHistory: 25,
  diagnosis: 15,
  geneticData: 25,
  financialData: 10,
  education: 0.75,
};

export interface InsightMetrics {
  totalTransactions: number;
  minimizedTransactions: number;
  blockedTransactions: number;
  withheldClaimsTotal: number;
  topDataConsumers: Array<{ name: string; count: number }>;
  exposureByDay: Record<string, number>;
  estimatedValueRetained: number;
}

const EMPTY_METRICS: InsightMetrics = {
  totalTransactions: 0,
  minimizedTransactions: 0,
  blockedTransactions: 0,
  withheldClaimsTotal: 0,
  topDataConsumers: [],
  exposureByDay: {},
  estimatedValueRetained: 0,
};

const dataFlowService = new DataFlowService();

export class InsightAggregator {
  static aggregate(entries: AuditLogEntry[]): InsightMetrics {
    const transactions = dataFlowService.buildTransactions(entries);

    if (transactions.length === 0) {
      return { ...EMPTY_METRICS };
    }

    let minimizedTransactions = 0;
    let blockedTransactions = 0;
    let withheldClaimsTotal = 0;
    let estimatedValueRetained = 0;
    const exposureByDay: Record<string, number> = {};
    const consumerCounts = new Map<string, number>();

    for (const transaction of transactions) {
      const withheldClaims = transaction.claimsWithheld ?? [];
      const usedPredicateProof = transaction.usedZKP && transaction.provenClaims.length > 0;
      const blocked = transaction.events.some(event => event.action === 'POLICY_BLOCKED');
      const day = transaction.startedAt.slice(0, 10);

      exposureByDay[day] = (exposureByDay[day] ?? 0) + 1;
      withheldClaimsTotal += withheldClaims.length;

      if (withheldClaims.length > 0 || usedPredicateProof) {
        minimizedTransactions++;
      }

      if (blocked) {
        blockedTransactions++;
      }

      if (transaction.verifierId) {
        consumerCounts.set(
          transaction.verifierLabel,
          (consumerCounts.get(transaction.verifierLabel) ?? 0) + 1
        );
      }

      for (const claim of withheldClaims) {
        estimatedValueRetained += CLAIM_VALUE_ESTIMATES[claim] ?? UNKNOWN_CLAIM_VALUE;
      }
    }

    const topDataConsumers = [...consumerCounts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

    return {
      totalTransactions: transactions.length,
      minimizedTransactions,
      blockedTransactions,
      withheldClaimsTotal,
      topDataConsumers,
      exposureByDay,
      estimatedValueRetained,
    };
  }
}
