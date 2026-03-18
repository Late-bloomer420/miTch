import { describe, it, expect } from 'vitest';
import { summarizeTransaction } from '../summary';
import type { DataFlowTransaction } from '../types';

function makeTxn(overrides: Partial<DataFlowTransaction> = {}): DataFlowTransaction {
  return {
    transactionId: 'test-001',
    startedAt: '2026-03-18T10:00:00Z',
    completedAt: '2026-03-18T10:00:05Z',
    verifierId: 'did:mitch:verifier-test',
    verifierLabel: 'Test',
    claimsShared: [],
    claimsRequested: null,
    claimsWithheld: null,
    provenClaims: [],
    credentialTypes: [],
    usedZKP: false,
    lifecycle: {
      keysCreated: 0,
      keysDestroyed: 0,
      fullyShredded: false,
      shreddingLatencyMs: null,
    },
    events: [],
    ...overrides,
  };
}

describe('summarizeTransaction', () => {
  it('returns empty points for minimal transaction', () => {
    const txn = makeTxn();
    const summary = summarizeTransaction(txn);
    expect(summary.points).toEqual([]);
  });

  // ZKP usage
  it('shows single proven claim name', () => {
    const txn = makeTxn({ usedZKP: true, provenClaims: ['age >= 18'] });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('age >= 18 bewiesen statt offengelegt');
  });

  it('shows count for multiple proven claims', () => {
    const txn = makeTxn({
      usedZKP: true,
      provenClaims: ['age >= 18', 'age >= 21'],
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points[0]).toBe('2 Eigenschaften bewiesen statt offengelegt');
  });

  it('does not mention ZKP if usedZKP is false', () => {
    const txn = makeTxn({ usedZKP: false, provenClaims: ['age >= 18'] });
    const summary = summarizeTransaction(txn);
    expect(summary.points.find(p => p.includes('bewiesen'))).toBeUndefined();
  });

  // Claims withheld
  it('shows single withheld claim name', () => {
    const txn = makeTxn({ claimsWithheld: ['address'] });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('address zurückgehalten');
  });

  it('shows count for multiple withheld claims', () => {
    const txn = makeTxn({ claimsWithheld: ['name', 'address', 'phone'] });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('3 Claims zurückgehalten');
  });

  it('does not mention withheld when null (fail-closed)', () => {
    const txn = makeTxn({ claimsWithheld: null });
    const summary = summarizeTransaction(txn);
    expect(summary.points.find(p => p.includes('zurückgehalten'))).toBeUndefined();
  });

  it('does not mention withheld when empty array', () => {
    const txn = makeTxn({ claimsWithheld: [] });
    const summary = summarizeTransaction(txn);
    expect(summary.points.find(p => p.includes('zurückgehalten'))).toBeUndefined();
  });

  // Shredding
  it('shows shredding with latency', () => {
    const txn = makeTxn({
      lifecycle: { keysCreated: 2, keysDestroyed: 2, fullyShredded: true, shreddingLatencyMs: 3200 },
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('Daten vergessen nach 3.2s');
  });

  it('shows shredding without latency', () => {
    const txn = makeTxn({
      lifecycle: { keysCreated: 2, keysDestroyed: 2, fullyShredded: true, shreddingLatencyMs: null },
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('Daten vergessen');
  });

  it('shows open keys when not fully shredded', () => {
    const txn = makeTxn({
      lifecycle: { keysCreated: 2, keysDestroyed: 1, fullyShredded: false, shreddingLatencyMs: null },
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('1 Schlüssel noch aktiv');
  });

  // Minimal disclosure
  it('shows no raw data shared when only proofs used', () => {
    const txn = makeTxn({
      claimsShared: [],
      provenClaims: ['age >= 18'],
      usedZKP: true,
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toContain('Keine Rohdaten geteilt');
  });

  it('does not show no-raw-data when claims were shared', () => {
    const txn = makeTxn({
      claimsShared: ['age'],
      provenClaims: ['age >= 18'],
      usedZKP: true,
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points.find(p => p.includes('Keine Rohdaten'))).toBeUndefined();
  });

  // Full scenario
  it('produces complete summary for typical transaction', () => {
    const txn = makeTxn({
      usedZKP: true,
      provenClaims: ['age >= 18'],
      claimsShared: [],
      claimsWithheld: ['name', 'address'],
      lifecycle: { keysCreated: 2, keysDestroyed: 2, fullyShredded: true, shreddingLatencyMs: 2500 },
    });
    const summary = summarizeTransaction(txn);
    expect(summary.points).toHaveLength(4);
    expect(summary.points[0]).toBe('age >= 18 bewiesen statt offengelegt');
    expect(summary.points[1]).toBe('2 Claims zurückgehalten');
    expect(summary.points[2]).toBe('Daten vergessen nach 2.5s');
    expect(summary.points[3]).toBe('Keine Rohdaten geteilt');
  });
});
