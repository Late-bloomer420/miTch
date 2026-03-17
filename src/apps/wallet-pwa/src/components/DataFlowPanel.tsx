import React, { useState, useMemo } from 'react';
import type { AuditLogEntry } from '@mitch/shared-types';
import { DataFlowService } from '@mitch/data-flow';
import type { DataFlowTransaction } from '@mitch/data-flow';

interface DataFlowPanelProps {
  entries: AuditLogEntry[];
}

const service = new DataFlowService();

export const DataFlowPanel: React.FC<DataFlowPanelProps> = ({ entries }) => {
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
}> = ({ txn, expanded, onToggle }) => {
  const timeStr = new Date(txn.startedAt).toLocaleString();

  return (
    <div className="dataflow-card">
      <div className="dataflow-card__header" onClick={onToggle}>
        <div className="dataflow-card__verifier">
          <strong>{txn.verifierLabel}</strong>
          <span className="dataflow-card__time">{timeStr}</span>
        </div>
        <div className="dataflow-card__status">
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
            {claim}
          </span>
        ))}
        {txn.provenClaims.map((claim) => (
          <span key={claim} className="dataflow-card__tag dataflow-card__tag--proven">
            {claim}
          </span>
        ))}
        {txn.claimsShared.length === 0 && txn.provenClaims.length === 0 && (
          <span className="dataflow-card__tag dataflow-card__tag--none">Keine Daten geteilt</span>
        )}
      </div>

      {expanded && (
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
      )}
    </div>
  );
};
