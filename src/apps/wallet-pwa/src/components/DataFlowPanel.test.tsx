import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import type { AuditLogEntry } from '@askmi/shared-types';
import { DataFlowPanel } from './DataFlowPanel';

/** A minimal VP_SENT audit entry — enough for DataFlowService to build one transaction. */
function vpSentEntry(decisionId: string): AuditLogEntry {
  return {
    id: `entry-${decisionId}`,
    timestamp: new Date().toISOString(),
    action: 'VP_SENT',
    verifierId: 'did:askmi:acme-verifier',
    previousHash: '0'.repeat(64),
    currentHash: '1'.repeat(64),
    metadata: {
      decision_id: decisionId,
      erasure_endpoint: 'https://rp.example/erase',
      claims_shared: ['age'],
    },
  };
}

describe('DataFlowPanel — GDPR action wiring', () => {
  it('invokes onAction with the transaction decision_id when the controls are used', () => {
    const onAction = vi.fn();
    const decisionId = 'dec-erase-1';

    render(<DataFlowPanel entries={[vpSentEntry(decisionId)]} onAction={onAction} />);

    // The per-transaction GDPR controls only exist once the card is expanded.
    fireEvent.click(screen.getByText('▼'));

    fireEvent.click(screen.getByText(/Löschung anfordern/));
    expect(onAction).toHaveBeenCalledWith('erasure', decisionId);

    fireEvent.click(screen.getByText(/Melden/));
    expect(onAction).toHaveBeenCalledWith('report', decisionId);
  });

  it('disables the erasure control when the transaction has no erasure endpoint', () => {
    const onAction = vi.fn();
    const entry = vpSentEntry('dec-no-endpoint');
    delete (entry.metadata as Record<string, unknown>).erasure_endpoint;

    render(<DataFlowPanel entries={[entry]} onAction={onAction} />);
    fireEvent.click(screen.getByText('▼'));

    const erasureBtn = screen.getByText(/Löschung anfordern/);
    fireEvent.click(erasureBtn);
    // Disabled: the click must not reach the handler (no false erasure request).
    expect(onAction).not.toHaveBeenCalledWith('erasure', 'dec-no-endpoint');
  });
});
