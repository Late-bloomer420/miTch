import { beforeEach, describe, expect, it } from 'vitest';
import { appendConsentReceiptHistory, buildConsentReceiptExport, loadConsentReceiptHistory } from '../receipt-store';

const RECEIPT_BASE = {
  verifier: 'did:mitch:verifier-liquor-store',
  purpose: 'Age verification',
  claimsShared: ['age'],
  timestamp: '2026-05-21T10:00:01.000Z',
};

beforeEach(() => {
  sessionStorage.clear();
});

describe('receipt-store', () => {
  it('appends and loads receipt history in reverse chronological order', () => {
    const first = appendConsentReceiptHistory({
      receipt: { ...RECEIPT_BASE, id: 'consent-1' },
      outcome: 'SUCCESS',
      decisionId: 'decision-1',
    });

    const second = appendConsentReceiptHistory({
      receipt: { ...RECEIPT_BASE, id: 'consent-2' },
      outcome: 'DENIED',
      decisionId: 'decision-2',
    });

    expect(first).toHaveLength(1);
    expect(second[0].receipt.id).toBe('consent-2');
    expect(loadConsentReceiptHistory()[0].receipt.id).toBe('consent-2');
  });

  it('deduplicates receipt ids', () => {
    appendConsentReceiptHistory({
      receipt: { ...RECEIPT_BASE, id: 'consent-1' },
      outcome: 'SUCCESS',
      decisionId: 'decision-1',
    });

    const next = appendConsentReceiptHistory({
      receipt: { ...RECEIPT_BASE, id: 'consent-1' },
      outcome: 'ERROR',
      decisionId: 'decision-1',
    });

    expect(next).toHaveLength(1);
    expect(next[0].outcome).toBe('ERROR');
  });

  it('ignores malformed storage payloads', () => {
    sessionStorage.setItem('mitch_consent_receipt_history', JSON.stringify([
      { receipt: { id: '', verifier: null, purpose: 'x', claimsShared: [], timestamp: 'bad' }, outcome: 'OK' },
      { receipt: { ...RECEIPT_BASE, id: 'consent-1' }, outcome: 'SUCCESS', decisionId: 'decision-1' },
    ]));

    const loaded = loadConsentReceiptHistory();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].receipt.id).toBe('consent-1');
  });

  it('exports metadata only', () => {
    const history = appendConsentReceiptHistory({
      receipt: { ...RECEIPT_BASE, id: 'consent-1' },
      outcome: 'SUCCESS',
      decisionId: 'decision-1',
    });

    const exportPayload = buildConsentReceiptExport(history);

    expect(exportPayload.count).toBe(1);
    expect(exportPayload.receipts[0]).toEqual({
      id: 'consent-1',
      verifier: RECEIPT_BASE.verifier,
      purpose: RECEIPT_BASE.purpose,
      claimsShared: RECEIPT_BASE.claimsShared,
      timestamp: RECEIPT_BASE.timestamp,
      outcome: 'SUCCESS',
      decisionId: 'decision-1',
    });
  });
});
