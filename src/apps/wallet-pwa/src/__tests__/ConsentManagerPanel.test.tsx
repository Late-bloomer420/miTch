/**
 * UX-09 — ConsentManagerPanel component tests
 *
 * Render-level coverage for the Consent Manager panel. These tests pin the
 * structural contract (heading, state badge, status badges, receipt history,
 * privacy note) so the UX-polish stylesheet work cannot silently regress the
 * markup the CSS hooks into. No business logic is exercised here.
 */

import { render, screen, fireEvent, within } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';

import { ConsentManagerPanel } from '../components/ConsentManagerPanel';
import type { StoredConsentReceiptEntry } from '../consent-manager/receipt-store';
import type { ConsentReceipt } from '@askmi/oid4vp';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeReceipt(overrides: Partial<ConsentReceipt> = {}): ConsentReceipt {
  return {
    id: 'receipt-001',
    verifier: 'did:web:liquor-store.example.com',
    purpose: 'Age verification for alcohol purchase',
    claimsShared: ['age_over_18'],
    timestamp: new Date().toISOString(),
    decisionId: 'decision-abc-001',
    ...overrides,
  };
}

function makeEntry(
  outcome: StoredConsentReceiptEntry['outcome'],
  receiptOverrides: Partial<ConsentReceipt> = {},
): StoredConsentReceiptEntry {
  return {
    receipt: makeReceipt(receiptOverrides),
    outcome,
    decisionId: 'decision-abc-001',
  };
}

function renderPanel(receiptHistory: StoredConsentReceiptEntry[] = []) {
  const onOpenDataFlow = vi.fn();
  const utils = render(
    <ConsentManagerPanel
      request={null}
      result={null}
      auditEntries={[]}
      privacyConsent={null}
      consentReceipt={null}
      receiptHistory={receiptHistory}
      onOpenDataFlow={onOpenDataFlow}
    />,
  );
  return { ...utils, onOpenDataFlow };
}

// ── Structure ───────────────────────────────────────────────────────────────

describe('ConsentManagerPanel — Structure', () => {
  it('renders the panel heading and subtitle', () => {
    renderPanel();
    expect(screen.getByText('Consent Manager')).toBeInTheDocument();
    expect(
      screen.getByText(/Requested, allowed, withheld, decision and evidence/i),
    ).toBeInTheDocument();
  });

  it('shows the idle state badge when there is no active decision', () => {
    const { container } = renderPanel();
    const badge = container.querySelector('.consent-manager-panel__state-badge');
    expect(badge).not.toBeNull();
    expect(badge).toHaveClass('consent-manager-panel__state-badge--idle');
    expect(badge).toHaveTextContent('Idle');
  });

  it('no longer renders the legacy inline-styled badge palette', () => {
    const { container } = renderPanel();
    const badge = container.querySelector('.consent-manager-panel__state-badge');
    // The polish moved colours into CSS classes — the element must not carry
    // a hardcoded inline background any more.
    expect(badge?.getAttribute('style')).toBeFalsy();
  });

  it('renders the four summary cards (Requested / Allowed / Withheld / Evidence)', () => {
    renderPanel();
    expect(screen.getByText('Requested')).toBeInTheDocument();
    expect(screen.getByText('Allowed')).toBeInTheDocument();
    expect(screen.getByText('Withheld')).toBeInTheDocument();
    expect(screen.getByText('Evidence')).toBeInTheDocument();
  });
});

// ── Receipt history ───────────────────────────────────────────────────────────

describe('ConsentManagerPanel — Receipt history', () => {
  it('shows the empty state and disables export when there are no receipts', () => {
    renderPanel([]);
    expect(screen.getByText('No stored consent receipts yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export JSON/i })).toBeDisabled();
  });

  it('renders a green SUCCESS status badge for a successful receipt', () => {
    const { container } = renderPanel([makeEntry('SUCCESS')]);
    const pill = container.querySelector('.consent-manager-panel__history-pill');
    expect(pill).not.toBeNull();
    expect(pill).toHaveClass('consent-manager-panel__history-pill--success');
    expect(pill).toHaveTextContent('SUCCESS');
  });

  it('renders a red DENIED status badge for a denied receipt', () => {
    const { container } = renderPanel([
      makeEntry('DENIED', { id: 'receipt-denied', claimsShared: [] }),
    ]);
    const pill = container.querySelector(
      '.consent-manager-panel__history-pill--denied',
    );
    expect(pill).not.toBeNull();
    expect(pill).toHaveTextContent('DENIED');
  });

  it('auto-selects the first receipt and surfaces the no-raw-PII guarantee', () => {
    renderPanel([makeEntry('SUCCESS')]);
    // Receipt detail card renders the privacy guarantee once a receipt is selected.
    expect(
      screen.getByText(/Receipt history stores only metadata\. No raw PII is persisted here\./i),
    ).toBeInTheDocument();
  });

  it('filters the history by verifier text', () => {
    const { container } = renderPanel([
      makeEntry('SUCCESS', { id: 'receipt-liquor', verifier: 'did:web:liquor-store.example.com' }),
      makeEntry('DENIED', { id: 'receipt-bank', verifier: 'did:web:shady-bank.example.com' }),
    ]);
    const input = screen.getByPlaceholderText(/Filter by verifier or purpose/i);
    fireEvent.change(input, { target: { value: 'shady-bank' } });

    const history = container.querySelector('.consent-manager-panel__history');
    expect(history).not.toBeNull();
    const items = within(history as HTMLElement).getAllByRole('button');
    expect(items).toHaveLength(1);
    expect(history).toHaveTextContent('receipt-bank');
    expect(history).not.toHaveTextContent('receipt-liquor');
  });
});

// ── Actions ─────────────────────────────────────────────────────────────────

describe('ConsentManagerPanel — Actions', () => {
  it('invokes onOpenDataFlow when the transaction-trace button is clicked', () => {
    const { onOpenDataFlow } = renderPanel();
    fireEvent.click(screen.getByRole('button', { name: /Open transaction trace/i }));
    expect(onOpenDataFlow).toHaveBeenCalledOnce();
  });
});
