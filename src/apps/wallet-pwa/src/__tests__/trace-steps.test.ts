import { describe, expect, it } from 'vitest';
import type { DataFlowTransaction } from '@askmi/data-flow';
import { describeTraceSteps } from '../utils/trace-steps';

const txn = (overrides: Partial<DataFlowTransaction>): DataFlowTransaction =>
  ({
    transactionId: 't1',
    startedAt: '2026-10-25T12:00:00.000Z',
    completedAt: null,
    verifierId: 'did:example:verifier',
    verifierLabel: 'Liquor Store',
    claimsShared: [],
    claimsRequested: null,
    claimsWithheld: null,
    provenClaims: [],
    credentialTypes: [],
    usedZKP: false,
    events: [],
    ...overrides,
  }) as DataFlowTransaction;

describe('describeTraceSteps', () => {
  it('shows waiting states before any transaction exists', () => {
    expect(describeTraceSteps(undefined)).toEqual({
      requested: 'Waiting',
      allowed: 'Idle',
      sent: 'Nothing yet',
    });
  });

  it('counts requested items, shows the verdict and what left the wallet', () => {
    const steps = describeTraceSteps(
      txn({
        verdict: 'ALLOW',
        claimsRequested: ['age >= 18'],
        provenClaims: ['age >= 18'],
        claimsShared: [],
      })
    );
    expect(steps).toEqual({ requested: '1 item', allowed: 'ALLOW', sent: '1 proof · 0 raw' });
  });

  it('mentions withheld claims in the sent step', () => {
    const steps = describeTraceSteps(
      txn({
        verdict: 'ALLOW',
        claimsRequested: ['givenName', 'birthDate', 'address'],
        claimsShared: ['givenName'],
        claimsWithheld: ['birthDate', 'address'],
      })
    );
    expect(steps.requested).toBe('3 items');
    expect(steps.sent).toBe('0 proofs · 1 raw · 2 withheld');
  });

  it('says nothing was sent on a deny', () => {
    const steps = describeTraceSteps(txn({ verdict: 'DENY', claimsRequested: ['address'] }));
    expect(steps).toEqual({ requested: '1 item', allowed: 'DENY', sent: 'Nothing sent' });
  });

  it('falls back to counting what is known when the request list was not logged', () => {
    const steps = describeTraceSteps(
      txn({ verdict: 'ALLOW', provenClaims: ['age >= 18'], claimsShared: ['role'] })
    );
    expect(steps.requested).toBe('2 items');
  });
});
