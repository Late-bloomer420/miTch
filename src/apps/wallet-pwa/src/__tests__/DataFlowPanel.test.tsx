/**
 * DataFlowPanel component tests
 */

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { DataFlowPanel } from '../components/DataFlowPanel';
import type { AuditLogEntry } from '@mitch/shared-types';

function makeEntry(
  overrides: Partial<AuditLogEntry> & Pick<AuditLogEntry, 'action'>
): AuditLogEntry {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    previousHash: '0'.repeat(64),
    currentHash: 'a'.repeat(64),
    ...overrides,
  };
}

const DEC_ID = 'decision-panel-001';

function buildTypicalEntries(): AuditLogEntry[] {
  const t0 = '2026-03-15T10:00:00Z';
  const t1 = '2026-03-15T10:00:01Z';
  const t2 = '2026-03-15T10:00:02Z';
  return [
    makeEntry({
      action: 'KEY_CREATED',
      timestamp: t0,
      metadata: { decision_id: DEC_ID, alg: 'ECDSA-P256' },
    }),
    makeEntry({
      action: 'VP_GENERATED',
      timestamp: t1,
      metadata: {
        decision_id: DEC_ID,
        verifier_did: 'did:mitch:verifier-liquor-store',
        claims_shared: ['age'],
        credential_types: ['AgeCredential'],
        proven_claims: ['age >= 18'],
        used_zkp: true,
      },
    }),
    makeEntry({
      action: 'KEY_DESTROYED',
      timestamp: t2,
      metadata: { decision_id: DEC_ID, verified: true },
    }),
  ];
}

describe('DataFlowPanel', () => {
  it('renders empty state when no entries', () => {
    render(<DataFlowPanel entries={[]} />);
    expect(screen.getByText('Noch keine Transaktionen')).toBeInTheDocument();
  });

  it('renders transaction with verifier label', () => {
    render(<DataFlowPanel entries={buildTypicalEntries()} />);
    expect(screen.getByText('Liquor Store')).toBeInTheDocument();
  });

  it('shows "Vergessen" when fully shredded', () => {
    render(<DataFlowPanel entries={buildTypicalEntries()} />);
    expect(screen.getByText('Vergessen')).toBeInTheDocument();
  });

  it('shows "Schlüssel aktiv" when not fully shredded', () => {
    const entries = [
      makeEntry({
        action: 'KEY_CREATED',
        metadata: { decision_id: DEC_ID },
      }),
    ];
    render(<DataFlowPanel entries={entries} />);
    expect(screen.getByText('Schlüssel aktiv')).toBeInTheDocument();
  });

  it('shows claims as tags', () => {
    render(<DataFlowPanel entries={buildTypicalEntries()} />);
    expect(screen.getByText('age')).toBeInTheDocument();
    expect(screen.getByText('age >= 18')).toBeInTheDocument();
  });

  it('shows withheld claims as tags when claims_requested present', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        timestamp: '2026-03-15T10:00:00Z',
        metadata: {
          decision_id: DEC_ID,
          verifier_did: 'did:mitch:verifier-hospital',
          claims_shared: ['age'],
          claims_requested: ['age', 'name', 'address'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ];
    render(<DataFlowPanel entries={entries} />);
    expect(screen.getByText('name')).toBeInTheDocument();
    expect(screen.getByText('address')).toBeInTheDocument();
  });

  it('does not show withheld section when claims_requested missing', () => {
    render(<DataFlowPanel entries={buildTypicalEntries()} />);
    // buildTypicalEntries has no claims_requested → no withheld tags
    expect(screen.queryByText('name')).not.toBeInTheDocument();
    expect(screen.queryByText('address')).not.toBeInTheDocument();
  });

  it('expands event timeline on click', () => {
    render(<DataFlowPanel entries={buildTypicalEntries()} />);
    // Timeline should not be visible initially
    expect(screen.queryByText('Sitzungsschlüssel erzeugt')).not.toBeInTheDocument();

    // Click the header to expand
    fireEvent.click(screen.getByText('Liquor Store'));
    expect(screen.getByText('Sitzungsschlüssel erzeugt')).toBeInTheDocument();
    expect(screen.getByText('Präsentation erstellt')).toBeInTheDocument();
    expect(screen.getByText('Schlüssel vernichtet')).toBeInTheDocument();
  });
});
