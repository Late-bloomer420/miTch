import React, { useEffect, useMemo, useState } from 'react';
import type { AuditLogEntry, PolicyEvaluationResult, VerifierRequest } from '@askmi/shared-types';
import type { PrivacyConsent } from '../services/PrivacyAuditService';
import type { ConsentReceipt } from '@askmi/oid4vp';
import { buildConsentManagerViewModel } from '../consent-manager/model';
import { buildConsentReceiptExport, type StoredConsentReceiptEntry } from '../consent-manager/receipt-store';

interface ConsentManagerPanelProps {
  request: VerifierRequest | null;
  result: PolicyEvaluationResult | null;
  auditEntries: AuditLogEntry[];
  privacyConsent: PrivacyConsent | null;
  consentReceipt: ConsentReceipt | null;
  receiptHistory: StoredConsentReceiptEntry[];
  onOpenDataFlow: () => void;
}

function claimLabel(value: string): string {
  return value.replace(/_/g, ' ');
}

function formatReceiptTime(timestamp: string): string {
  try {
    return new Date(timestamp).toLocaleString();
  } catch {
    return timestamp;
  }
}

function matchesTimeframe(timestamp: string, timeframe: 'all' | '24h' | '7d' | '30d'): boolean {
  if (timeframe === 'all') return true;
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return false;
  const ageMs = Date.now() - date.getTime();
  const limits = {
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
  };
  return ageMs <= limits[timeframe];
}

const STATE_BADGE_LABELS: Record<'idle' | 'prompt' | 'approved' | 'denied', string> = {
  idle: 'Idle',
  prompt: 'Consent prompt',
  approved: 'Approved',
  denied: 'Denied',
};

function StateBadge({ state }: { state: 'idle' | 'prompt' | 'approved' | 'denied' }) {
  return (
    <span className={`consent-manager-panel__state-badge consent-manager-panel__state-badge--${state}`}>
      {STATE_BADGE_LABELS[state]}
    </span>
  );
}

export function ConsentManagerPanel({
  request,
  result,
  auditEntries,
  privacyConsent,
  consentReceipt,
  receiptHistory,
  onOpenDataFlow,
}: ConsentManagerPanelProps) {
  const [verifierFilter, setVerifierFilter] = useState('');
  const [timeframe, setTimeframe] = useState<'all' | '24h' | '7d' | '30d'>('all');
  const [selectedReceiptId, setSelectedReceiptId] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 5;

  const model = buildConsentManagerViewModel({
    request,
    result,
    auditEntries,
    privacyConsent,
    consentReceipt,
  });

  const filteredHistory = useMemo(() => {
    const query = verifierFilter.trim().toLowerCase();
    return receiptHistory.filter(entry => {
      const verifier = entry.receipt.verifier.toLowerCase();
      const purpose = entry.receipt.purpose.toLowerCase();
      return matchesTimeframe(entry.receipt.timestamp, timeframe)
        && (!query || verifier.includes(query) || purpose.includes(query));
    });
  }, [receiptHistory, timeframe, verifierFilter]);

  const pageCount = Math.max(1, Math.ceil(filteredHistory.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const pagedHistory = useMemo(
    () => filteredHistory.slice(currentPage * pageSize, currentPage * pageSize + pageSize),
    [currentPage, filteredHistory]
  );

  useEffect(() => {
    if (filteredHistory.length === 0) {
      setSelectedReceiptId(null);
      setPage(0);
      return;
    }
    if (!selectedReceiptId || !filteredHistory.some(entry => entry.receipt.id === selectedReceiptId)) {
      setSelectedReceiptId(filteredHistory[0].receipt.id);
    }
    if (page !== currentPage) {
      setPage(currentPage);
    }
  }, [currentPage, filteredHistory, page, selectedReceiptId]);

  useEffect(() => {
    setPage(0);
  }, [timeframe, verifierFilter]);

  const selectedReceipt = filteredHistory.find(entry => entry.receipt.id === selectedReceiptId) ?? null;

  const handleExportHistory = () => {
    const report = buildConsentReceiptExport(filteredHistory);
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `mitch-consent-receipts-${ts}.json`;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <section className="consent-manager-panel">
      <div className="consent-manager-panel__header">
        <div>
          <h3 className="consent-manager-panel__title">Consent Manager</h3>
          <p className="consent-manager-panel__subtitle">
            Requested, allowed, withheld, decision and evidence in one view.
          </p>
        </div>
        <StateBadge state={model.state} />
      </div>

      <div className="consent-manager-panel__summary">
        <div>
          <div className="consent-manager-panel__label">Verifier</div>
          <div className="consent-manager-panel__value">{model.verifierLabel}</div>
        </div>
        <div>
          <div className="consent-manager-panel__label">Decision</div>
          <div className="consent-manager-panel__value">{model.decisionId ?? 'No decision yet'}</div>
        </div>
        <div>
          <div className="consent-manager-panel__label">Identity signals</div>
          <div className="consent-manager-panel__value">{model.identityAccessCount}</div>
        </div>
        <div>
          <div className="consent-manager-panel__label">Evidence items</div>
          <div className="consent-manager-panel__value">{model.evidence.length}</div>
        </div>
      </div>

      <div className="consent-manager-panel__grid">
        <article className="consent-manager-panel__card">
          <h4>Requested</h4>
          <div className="consent-manager-panel__chips">
            {model.requestedClaims.length > 0
              ? model.requestedClaims.map(claim => (
                  <span key={claim} className="consent-manager-panel__chip consent-manager-panel__chip--requested">
                    {claimLabel(claim)}
                  </span>
                ))
              : <span className="consent-manager-panel__empty">No raw claims requested</span>}
          </div>
        </article>

        <article className="consent-manager-panel__card">
          <h4>Allowed</h4>
          <div className="consent-manager-panel__chips">
            {model.provenClaims.length > 0
              ? model.provenClaims.map(claim => (
                  <span key={`proven-${claim}`} className="consent-manager-panel__chip consent-manager-panel__chip--allowed">
                    {claimLabel(claim)}
                  </span>
                ))
              : model.allowedClaims.length > 0
                ? model.allowedClaims.map(claim => (
                    <span key={claim} className="consent-manager-panel__chip consent-manager-panel__chip--allowed">
                      {claimLabel(claim)}
                    </span>
                  ))
                : <span className="consent-manager-panel__empty">Nothing disclosed yet</span>}
          </div>
        </article>

        <article className="consent-manager-panel__card">
          <h4>Withheld</h4>
          <div className="consent-manager-panel__chips">
            {model.withheldClaims && model.withheldClaims.length > 0
              ? model.withheldClaims.map(claim => (
                  <span key={claim} className="consent-manager-panel__chip consent-manager-panel__chip--withheld">
                    {claimLabel(claim)}
                  </span>
                ))
              : <span className="consent-manager-panel__empty">No withheld claims in the current view</span>}
          </div>
        </article>

        <article className="consent-manager-panel__card">
          <h4>Evidence</h4>
          <div className="consent-manager-panel__evidence">
            {model.evidence.map(item => (
              <div key={`${item.label}-${item.value}`} className="consent-manager-panel__evidence-item">
                <span className="consent-manager-panel__label">{item.label}</span>
                <span className="consent-manager-panel__value">{item.value}</span>
              </div>
            ))}
          </div>
        </article>
      </div>

      {model.identityAccesses.length > 0 && (
        <div className="consent-manager-panel__signals">
          <div className="consent-manager-panel__label">Identity signals</div>
          <div className="consent-manager-panel__chips">
            {model.identityAccesses.map((signal, index) => (
              <span
                key={`${signal.actor_label}-${index}`}
                className="consent-manager-panel__chip consent-manager-panel__chip--signal"
                title={`${signal.access_type} · ${signal.linkability}`}
              >
                {signal.actor_label}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="consent-manager-panel__actions">
        <button className="btn-demo-secondary" onClick={onOpenDataFlow}>
          Open transaction trace
        </button>
      </div>

      <article className="consent-manager-panel__card">
        <div className="consent-manager-panel__history-header">
          <h4>Receipt history</h4>
          <div className="consent-manager-panel__filters">
            <input
              className="consent-manager-panel__filter-input"
              type="search"
              value={verifierFilter}
              onChange={event => setVerifierFilter(event.target.value)}
              placeholder="Filter by verifier or purpose"
            />
            <select
              className="consent-manager-panel__filter-select"
              value={timeframe}
              onChange={event => setTimeframe(event.target.value as 'all' | '24h' | '7d' | '30d')}
            >
              <option value="all">All time</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
              <option value="30d">Last 30d</option>
            </select>
            <button className="btn-demo-secondary" onClick={handleExportHistory} disabled={filteredHistory.length === 0}>
              Export JSON
            </button>
          </div>
        </div>
        {filteredHistory.length > 0 ? (
          <div className="consent-manager-panel__history">
            {pagedHistory.map(entry => {
              const isSelected = entry.receipt.id === selectedReceiptId;
              return (
                <button
                  key={entry.receipt.id}
                  type="button"
                  className={`consent-manager-panel__history-item${isSelected ? ' consent-manager-panel__history-item--selected' : ''}`}
                  onClick={() => setSelectedReceiptId(entry.receipt.id)}
                >
                  <div className="consent-manager-panel__history-topline">
                    <strong>{entry.receipt.id}</strong>
                    <span className={`consent-manager-panel__history-pill consent-manager-panel__history-pill--${entry.outcome.toLowerCase()}`}>
                      {entry.outcome}
                    </span>
                  </div>
                  <div className="consent-manager-panel__history-meta">
                    <span>{entry.receipt.verifier}</span>
                    <span>{formatReceiptTime(entry.receipt.timestamp)}</span>
                    {entry.decisionId && <span>Decision {entry.decisionId}</span>}
                  </div>
                  <div className="consent-manager-panel__chips">
                    {entry.receipt.claimsShared.length > 0 ? (
                      entry.receipt.claimsShared.map(claim => (
                        <span key={`${entry.receipt.id}-${claim}`} className="consent-manager-panel__chip consent-manager-panel__chip--allowed">
                          {claimLabel(claim)}
                        </span>
                      ))
                    ) : (
                      <span className="consent-manager-panel__empty">No claims disclosed</span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        ) : (
          <div className="consent-manager-panel__empty">No stored consent receipts yet</div>
        )}
        {filteredHistory.length > pageSize && (
          <div className="consent-manager-panel__pagination">
            <button
              className="btn-demo-secondary"
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={currentPage === 0}
            >
              Previous
            </button>
            <span className="consent-manager-panel__pagination-label">
              Page {currentPage + 1} of {pageCount}
            </span>
            <button
              className="btn-demo-secondary"
              onClick={() => setPage(p => Math.min(pageCount - 1, p + 1))}
              disabled={currentPage >= pageCount - 1}
            >
              Next
            </button>
          </div>
        )}
      </article>

      <article className="consent-manager-panel__card">
        <h4>Receipt detail</h4>
        {selectedReceipt ? (
          <div className="consent-manager-panel__detail">
            <div className="consent-manager-panel__detail-row">
              <span className="consent-manager-panel__label">Receipt ID</span>
              <span className="consent-manager-panel__value">{selectedReceipt.receipt.id}</span>
            </div>
            <div className="consent-manager-panel__detail-row">
              <span className="consent-manager-panel__label">Verifier</span>
              <span className="consent-manager-panel__value">{selectedReceipt.receipt.verifier}</span>
            </div>
            <div className="consent-manager-panel__detail-row">
              <span className="consent-manager-panel__label">Purpose</span>
              <span className="consent-manager-panel__value">{selectedReceipt.receipt.purpose}</span>
            </div>
            <div className="consent-manager-panel__detail-row">
              <span className="consent-manager-panel__label">Timestamp</span>
              <span className="consent-manager-panel__value">{formatReceiptTime(selectedReceipt.receipt.timestamp)}</span>
            </div>
            <div className="consent-manager-panel__detail-row">
              <span className="consent-manager-panel__label">Decision</span>
              <span className="consent-manager-panel__value">{selectedReceipt.outcome}</span>
            </div>
            <div className="consent-manager-panel__detail-row">
              <span className="consent-manager-panel__label">Decision ID</span>
              <span className="consent-manager-panel__value">{selectedReceipt.decisionId ?? 'Unavailable'}</span>
            </div>
            <div className="consent-manager-panel__detail-block">
              <div className="consent-manager-panel__label">Shared claims</div>
              <div className="consent-manager-panel__chips">
                {selectedReceipt.receipt.claimsShared.length > 0 ? (
                  selectedReceipt.receipt.claimsShared.map(claim => (
                    <span key={`detail-${selectedReceipt.receipt.id}-${claim}`} className="consent-manager-panel__chip consent-manager-panel__chip--allowed">
                      {claimLabel(claim)}
                    </span>
                  ))
                ) : (
                  <span className="consent-manager-panel__empty">No claims disclosed</span>
                )}
              </div>
            </div>
            <div className="consent-manager-panel__empty">
              Receipt history stores only metadata. No raw PII is persisted here.
            </div>
          </div>
        ) : (
          <div className="consent-manager-panel__empty">Select a receipt to inspect its details.</div>
        )}
      </article>
    </section>
  );
}
