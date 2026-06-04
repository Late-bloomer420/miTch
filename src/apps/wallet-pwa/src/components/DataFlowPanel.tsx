import React, { useState, useMemo } from 'react';
import type { AuditLogEntry } from '@askmi/shared-types';
import { DataFlowService, summarizeTransaction } from '@askmi/data-flow';
import type { DataFlowTransaction } from '@askmi/data-flow';
import { translateClaim } from '../utils/i18n';

interface DataFlowPanelProps {
  entries: AuditLogEntry[];
  onAction?: (type: 'erasure' | 'report', decisionId: string) => void;
}

const service = new DataFlowService();

export const DataFlowPanel: React.FC<DataFlowPanelProps> = ({ entries, onAction }) => {
  const transactions = useMemo(() => service.buildTransactions(entries), [entries]);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (transactions.length === 0) {
    return (
      <div className="dataflow-panel">
        <h3 className="dataflow-panel__title">Datenflüsse</h3>
        <p className="dataflow-panel__empty">Noch keine Transaktionen</p>
      </div>
    );
  }

  return (
    <div className="dataflow-panel">
      <h3 className="dataflow-panel__title">Datenflüsse</h3>
      <div className="dataflow-panel__list">
        {transactions.map((txn) => (
          <TransactionCard
            key={txn.transactionId}
            txn={txn}
            expanded={expandedId === txn.transactionId}
            onToggle={() =>
              setExpandedId(expandedId === txn.transactionId ? null : txn.transactionId)
            }
            onAction={onAction}
          />
        ))}
      </div>
    </div>
  );
};

const TransactionCard: React.FC<{
  txn: DataFlowTransaction;
  expanded: boolean;
  onToggle: () => void;
  onAction?: (type: 'erasure' | 'report', decisionId: string) => void;
}> = ({ txn, expanded, onToggle, onAction }) => {
  const timeStr = new Date(txn.startedAt).toLocaleString();
  const summary = useMemo(() => summarizeTransaction(txn), [txn]);

  const hasErasureEndpoint = txn.events.some(e => e.action === 'VP_SENT' && e.metadata?.erasure_endpoint);

  return (
    <div className="dataflow-card">
      <div className="dataflow-card__header" onClick={onToggle}>
        <div className="dataflow-card__verifier">
          <strong>{txn.verifierLabel}</strong>
          <span className="dataflow-card__time">{timeStr}</span>
        </div>
        <div className="dataflow-card__status">
          {txn.identityAccessCount > 0 && (
            <span className="dataflow-card__identity" title="Identifier-Zugriffe sichtbar gemacht">
              {txn.identityAccessCount} Identifier
            </span>
          )}
          {txn.lifecycle.fullyShredded ? (
            <span className="dataflow-card__shredded" title="Alle Schlüssel vernichtet">
              Vergessen
            </span>
          ) : (
            <span className="dataflow-card__active" title="Schlüssel noch aktiv">
              Schlüssel aktiv
            </span>
          )}
          <span className="dataflow-card__toggle">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      <div className="dataflow-card__claims">
        {txn.claimsShared.map((claim) => (
          <span key={claim} className="dataflow-card__tag dataflow-card__tag--claim">
            {translateClaim(claim)}
          </span>
        ))}
        {txn.provenClaims.map((claim) => (
          <span key={claim} className="dataflow-card__tag dataflow-card__tag--proven">
            {translateClaim(claim)}
          </span>
        ))}
        {txn.claimsWithheld !== null && txn.claimsWithheld.length > 0 &&
          txn.claimsWithheld.map((claim) => (
            <span key={`withheld-${claim}`} className="dataflow-card__tag dataflow-card__tag--withheld">
              {translateClaim(claim)}
            </span>
          ))}
        {txn.identityAccessCount > 0 && (
          <span className="dataflow-card__tag dataflow-card__tag--identity">
            Identifier sichtbar gemacht
          </span>
        )}
        {txn.claimsShared.length === 0 && txn.provenClaims.length === 0 && (
          <span className="dataflow-card__tag dataflow-card__tag--none">Keine Daten geteilt</span>
        )}
      </div>

      {summary.points.length > 0 && (
        <div className="dataflow-card__summary">
          {summary.points.map((point, i) => (
            <span key={i} className="dataflow-card__summary-point">{point}</span>
          ))}
        </div>
      )}

      {expanded && (
        <>
          <div className="dataflow-card__timeline">
            {txn.events.map((evt) => (
              <div key={evt.auditEntryId} className="dataflow-event">
                <span className={`dataflow-event__dot dataflow-event__dot--${evt.category}`} />
                <span className="dataflow-event__time">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </span>
                <span className="dataflow-event__label">{evt.label}</span>
              </div>
            ))}
          </div>

          <div className="dataflow-card__actions" style={{ marginTop: 15, display: 'flex', gap: 10 }}>
            <button
              className="btn-compliance btn-compliance--erasure"
              onClick={() => onAction?.('erasure', txn.transactionId)}
              title="Datenlöschung gemäß DSGVO Art. 17 anfordern"
              disabled={!hasErasureEndpoint}
              style={{
                  background: '#1e293b', border: '1px solid #475569', borderRadius: 4,
                  color: hasErasureEndpoint ? '#cbd5e1' : '#64748b', fontSize: 11,
                  padding: '4px 8px', cursor: hasErasureEndpoint ? 'pointer' : 'not-allowed'
              }}
            >
              🗑️ Löschung anfordern
            </button>
            <button
              className="btn-compliance btn-compliance--report"
              onClick={() => onAction?.('report', txn.transactionId)}
              title="Diesen Verifier der Aufsichtsbehörde melden"
              style={{
                  background: '#1e293b', border: '1px solid #475569', borderRadius: 4,
                  color: '#f87171', fontSize: 11, padding: '4px 8px', cursor: 'pointer'
              }}
            >
              🚩 Melden
            </button>
          </div>
        </>
      )}
    </div>
  );
};

