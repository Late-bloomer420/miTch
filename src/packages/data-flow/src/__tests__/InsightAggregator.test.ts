import { describe, expect, it } from 'vitest';
import { InsightAggregator } from '../InsightAggregator';
import type { AuditLogEntry } from '@askmi/shared-types';

function makeEntry(
  overrides: Partial<AuditLogEntry> & Pick<AuditLogEntry, 'action'>
): AuditLogEntry {
  return {
    id: crypto.randomUUID(),
    timestamp: '2026-06-04T10:00:00.000Z',
    previousHash: '0'.repeat(64),
    currentHash: 'a'.repeat(64),
    ...overrides,
  };
}

describe('InsightAggregator', () => {
  it('returns zero metrics for empty input', () => {
    expect(InsightAggregator.aggregate([])).toEqual({
      totalTransactions: 0,
      minimizedTransactions: 0,
      blockedTransactions: 0,
      withheldClaimsTotal: 0,
      topDataConsumers: [],
      exposureByDay: {},
      estimatedValueRetained: 0,
    });
  });

  it('aggregates current snake_case audit metadata through DataFlowService', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: 'decision-001',
          verifier_did: 'did:askmi:verifier-hospital',
          claims_shared: ['age'],
          claims_requested: ['age', 'name', 'address'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ]);

    expect(metrics.totalTransactions).toBe(1);
    expect(metrics.minimizedTransactions).toBe(1);
    expect(metrics.withheldClaimsTotal).toBe(2);
    expect(metrics.topDataConsumers).toEqual([{ name: 'Hospital', count: 1 }]);
    expect(metrics.exposureByDay).toEqual({ '2026-06-04': 1 });
    expect(metrics.estimatedValueRetained).toBeCloseTo(2);
  });

  it('counts withheld claims from normalized transactions, not stale camelCase metadata', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: 'decision-002',
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_shared: ['age'],
          claims_requested: ['age', 'birthDate', 'unknownClaim'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ]);

    expect(metrics.withheldClaimsTotal).toBe(2);
    expect(metrics.estimatedValueRetained).toBeCloseTo(1.3);
  });

  it('counts ZKP-only age proof transactions as minimized', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: 'decision-003',
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_shared: [],
          credential_types: ['AgeCredential'],
          proven_claims: ['age >= 18'],
          used_zkp: true,
        },
      }),
    ]);

    expect(metrics.minimizedTransactions).toBe(1);
    expect(metrics.withheldClaimsTotal).toBe(0);
  });

  it('counts policy-blocked transactions', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'POLICY_BLOCKED',
        metadata: {
          decision_id: 'decision-004',
          reason: 'VERIFIER_BLOCKED',
        },
      }),
    ]);

    expect(metrics.totalTransactions).toBe(1);
    expect(metrics.blockedTransactions).toBe(1);
    expect(metrics.topDataConsumers).toEqual([]);
  });

  it('aggregates and sorts top data consumers', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'VP_GENERATED',
        timestamp: '2026-06-04T10:00:00.000Z',
        metadata: {
          decision_id: 'decision-005',
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_shared: ['age'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
      makeEntry({
        action: 'VP_GENERATED',
        timestamp: '2026-06-04T11:00:00.000Z',
        metadata: {
          decision_id: 'decision-006',
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_shared: ['age'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
      makeEntry({
        action: 'VP_GENERATED',
        timestamp: '2026-06-04T12:00:00.000Z',
        metadata: {
          decision_id: 'decision-007',
          verifier_did: 'did:askmi:verifier-hospital',
          claims_shared: ['age'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ]);

    expect(metrics.topDataConsumers).toEqual([
      { name: 'Liquor Store', count: 2 },
      { name: 'Hospital', count: 1 },
    ]);
  });

  it('aggregates exposure by transaction day', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'KEY_CREATED',
        timestamp: '2026-06-03T23:59:00.000Z',
        metadata: { decision_id: 'decision-008' },
      }),
      makeEntry({
        action: 'KEY_CREATED',
        timestamp: '2026-06-04T00:01:00.000Z',
        metadata: { decision_id: 'decision-009' },
      }),
    ]);

    expect(metrics.exposureByDay).toEqual({
      '2026-06-04': 1,
      '2026-06-03': 1,
    });
  });

  it('handles legacy transactions without claims_requested', () => {
    const metrics = InsightAggregator.aggregate([
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: 'decision-010',
          verifier_did: 'did:askmi:verifier-legacy',
          claims_shared: ['age'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ]);

    expect(metrics.totalTransactions).toBe(1);
    expect(metrics.withheldClaimsTotal).toBe(0);
    expect(metrics.estimatedValueRetained).toBe(0);
  });
});
