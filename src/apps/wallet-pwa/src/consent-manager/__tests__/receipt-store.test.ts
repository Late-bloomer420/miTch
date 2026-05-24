import { beforeEach, describe, expect, it } from 'vitest';
import { appendConsentReceiptHistory, buildConsentReceiptExport, loadConsentReceiptHistory } from '../receipt-store';

const RECEIPT_BASE = {
  schemaVersion: 1 as const,
  verifier: 'did:mitch:verifier-liquor-store',
  purpose: 'Age verification',
  claimsShared: ['age'],
  timestamp: '2026-05-21T10:00:01.000Z',
  outcome: 'SUCCESS' as const,
  decisionId: 'decision-1',
};

beforeEach(() => {
  sessionStorage.clear();
});

describe('receipt-store', () => {
  it('appends and loads receipt history in reverse chronological order', () => {
    const first = appendConsentReceiptHistory({ ...RECEIPT_BASE, id: 'consent-1' });

    const second = appendConsentReceiptHistory({
      ...RECEIPT_BASE,
      id: 'consent-2',
      outcome: 'DENIED',
      decisionId: 'decision-2',
    });

    expect(first).toHaveLength(1);
    expect(second[0].id).toBe('consent-2');
    expect(loadConsentReceiptHistory()[0].id).toBe('consent-2');
  });

  it('deduplicates receipt ids', () => {
    appendConsentReceiptHistory({ ...RECEIPT_BASE, id: 'consent-1' });

    const next = appendConsentReceiptHistory({
      ...RECEIPT_BASE,
      id: 'consent-1',
      outcome: 'ERROR',
    });

    expect(next).toHaveLength(1);
    expect(next[0].outcome).toBe('ERROR');
  });

  it('normalizes legacy wrapper payloads from storage', () => {
    sessionStorage.setItem('mitch_consent_receipt_history', JSON.stringify([
      {
        receipt: { ...RECEIPT_BASE, id: 'consent-legacy' },
        outcome: 'SUCCESS',
        decisionId: 'decision-legacy',
      },
    ]));

    const loaded = loadConsentReceiptHistory();
    expect(loaded).toHaveLength(1);
    expect(loaded[0]).toMatchObject({
      id: 'consent-legacy',
      outcome: 'SUCCESS',
      decisionId: 'decision-legacy',
      schemaVersion: 1,
    });
  });

  it('exports metadata with scope and hash binding', async () => {
    const history = appendConsentReceiptHistory({ ...RECEIPT_BASE, id: 'consent-1' });

    const options = {
      scope: 'filtered' as const,
      filters: {
        verifierQuery: 'liquor',
        timeframe: '7d' as const,
      },
      auditAnchorHash: 'audit-hash-001',
    };

    const first = await buildConsentReceiptExport(history, options);
    const second = await buildConsentReceiptExport(history, options);
    const mutated = await buildConsentReceiptExport([
      { ...history[0], claimsShared: ['age', 'name'] },
    ], options);

    expect(first.scope).toBe('filtered');
    expect(first.filters).toEqual(options.filters);
    expect(first.count).toBe(1);
    expect(first.auditAnchorHash).toBe('audit-hash-001');
    expect(first.receipts[0]).toMatchObject(RECEIPT_BASE);
    expect(first.receipts[0].schemaVersion).toBe(1);
    expect(first.receiptSetHash).toBe(second.receiptSetHash);
    expect(first.exportHash).toBe(second.exportHash);
    expect(mutated.receiptSetHash).not.toBe(first.receiptSetHash);
  });
});
