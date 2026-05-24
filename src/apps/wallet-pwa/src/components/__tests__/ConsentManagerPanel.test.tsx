import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { AuditLogEntry, PolicyEvaluationResult, VerifierRequest } from '@mitch/shared-types';
import type { PrivacyConsent } from '../../services/PrivacyAuditService';
import type { ConsentReceipt } from '../../consent-manager/types';

const buildConsentReceiptExportMock = vi.hoisted(() => vi.fn());

vi.mock('../../consent-manager/receipt-store', async () => {
  const actual = await vi.importActual<typeof import('../../consent-manager/receipt-store')>('../../consent-manager/receipt-store');
  return {
    ...actual,
    buildConsentReceiptExport: buildConsentReceiptExportMock,
  };
});

import { ConsentManagerPanel } from '../ConsentManagerPanel';

function makeEntry(
  overrides: Partial<AuditLogEntry> & Pick<AuditLogEntry, 'action'>
): AuditLogEntry {
  return {
    id: overrides.id ?? `entry-${crypto.randomUUID()}`,
    timestamp: overrides.timestamp ?? '2026-05-21T10:00:00.000Z',
    action: overrides.action,
    previousHash: overrides.previousHash ?? 'prev',
    currentHash: overrides.currentHash ?? 'curr',
    metadata: overrides.metadata ?? {},
  };
}

function makeReceipt(index: number, overrides: Partial<ConsentReceipt> = {}): ConsentReceipt {
  return {
    schemaVersion: 1,
    id: overrides.id ?? `consent-${index}`,
    verifier: overrides.verifier ?? (index % 2 === 0 ? 'did:mitch:verifier-hospital' : 'did:mitch:verifier-liquor-store'),
    purpose: overrides.purpose ?? 'Age verification',
    claimsShared: overrides.claimsShared ?? ['age'],
    timestamp: overrides.timestamp ?? `2026-05-21T10:0${index}:00.000Z`,
    outcome: overrides.outcome ?? 'SUCCESS',
    decisionId: overrides.decisionId ?? `decision-${index}`,
  };
}

const request: VerifierRequest = {
  verifierId: 'did:mitch:verifier-liquor-store',
  requestedClaims: ['age', 'name', 'address'],
  requestedProvenClaims: ['age >= 18'],
};

const result: PolicyEvaluationResult = {
  verdict: 'PROMPT',
  reasonCodes: ['CONSENT_REQUIRED'],
  decisionCapsule: {
    decision_id: 'decision-001',
    verdict: 'PROMPT',
    request_hash: 'req-hash',
    policy_hash: 'policy-hash',
    verifier_did: 'did:mitch:verifier-liquor-store',
    authorized_requirements: [
      {
        credential_type: 'AgeCredential',
        allowed_claims: ['age'],
        proven_claims: ['age >= 18'],
        selected_credential_id: 'vc-1',
        issuer_trust_refs: [],
        requested_claims: ['age', 'name', 'address'],
      },
    ],
    risk_level: 'LOW',
    requires_presence: false,
    expires_at: '2026-05-21T10:05:00.000Z',
    audience: 'wallet-pwa',
    issued_at: '2026-05-21T10:00:00.000Z',
  },
};

const auditEntries = [
  makeEntry({
    action: 'VP_GENERATED',
    metadata: {
      decision_id: 'decision-001',
      claims_shared: ['age'],
      claims_requested: ['age', 'name', 'address'],
      proven_claims: ['age >= 18'],
      credential_types: ['AgeCredential'],
      used_zkp: true,
    },
  }),
];

const privacyConsent: PrivacyConsent = {
  status: 'ACCEPT',
  acceptedTrackers: ['Google Chrome'],
  timestamp: '2026-05-21T10:00:00.000Z',
  auditHash: 'abc123',
};

const receiptHistory = Array.from({ length: 7 }, (_, index) => makeReceipt(index + 1));

beforeEach(() => {
  vi.restoreAllMocks();
  buildConsentReceiptExportMock.mockReset();
  buildConsentReceiptExportMock.mockResolvedValue({
    exportedAt: '2026-05-21T10:00:00.000Z',
    scope: 'filtered',
    filters: { verifierQuery: '', timeframe: 'all' },
    count: 0,
    auditAnchorHash: null,
    receiptSetHash: 'hash-1',
    exportHash: 'hash-2',
    receipts: [],
  });
  Object.defineProperty(URL, 'createObjectURL', { value: vi.fn(() => 'blob:mock'), configurable: true });
  Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), configurable: true });
  vi.spyOn(document.body, 'appendChild');
  vi.spyOn(document.body, 'removeChild');
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
});

describe('ConsentManagerPanel', () => {
  it('filters, paginates and shows receipt details', () => {
    render(
      <ConsentManagerPanel
        request={request}
        result={result}
        auditEntries={auditEntries}
        privacyConsent={privacyConsent}
        consentReceipt={receiptHistory[0]}
        receiptHistory={receiptHistory}
        onOpenDataFlow={vi.fn()}
      />
    );

    expect(screen.getByText('Receipt history')).toBeInTheDocument();
    expect(screen.getByText(/OID4VP W-05 receipts are the only persisted consent history right now\./i)).toBeInTheDocument();
    expect(screen.getAllByText('consent-1').length).toBeGreaterThan(0);
    expect(screen.queryByText('consent-6')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Next/i }));
    expect(screen.getByText('consent-6')).toBeInTheDocument();

    fireEvent.click(screen.getByText('consent-6'));
    expect(screen.getAllByText('Decision ID').length).toBeGreaterThan(0);
    expect(screen.getByText('decision-6')).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText('Filter by verifier or purpose'), { target: { value: 'hospital' } });
    expect(screen.getByText('consent-2')).toBeInTheDocument();
  });

  it('exports filtered and full history separately', async () => {
    render(
      <ConsentManagerPanel
        request={request}
        result={result}
        auditEntries={auditEntries}
        privacyConsent={privacyConsent}
        consentReceipt={receiptHistory[0]}
        receiptHistory={receiptHistory}
        onOpenDataFlow={vi.fn()}
      />
    );

    fireEvent.change(screen.getByPlaceholderText('Filter by verifier or purpose'), { target: { value: 'hospital' } });
    fireEvent.click(screen.getByRole('button', { name: /Export filtered JSON/i }));

    await waitFor(() => {
      expect(buildConsentReceiptExportMock).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ verifier: 'did:mitch:verifier-hospital' }),
        ]),
        expect.objectContaining({
          scope: 'filtered',
          filters: { verifierQuery: 'hospital', timeframe: 'all' },
          auditAnchorHash: 'curr',
        })
      );
    });

    buildConsentReceiptExportMock.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Export full history JSON/i }));

    await waitFor(() => {
      expect(buildConsentReceiptExportMock).toHaveBeenCalledWith(
        receiptHistory,
        expect.objectContaining({
          scope: 'full',
          filters: { verifierQuery: 'hospital', timeframe: 'all' },
          auditAnchorHash: 'curr',
        })
      );
    });
  });
});
