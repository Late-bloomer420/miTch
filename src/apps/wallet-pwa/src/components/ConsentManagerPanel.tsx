import React from 'react';
import type { AuditLogEntry, PolicyEvaluationResult, VerifierRequest } from '@mitch/shared-types';
import type { PrivacyConsent } from '../services/PrivacyAuditService';
import { buildConsentManagerViewModel } from '../consent-manager/model';

interface ConsentManagerPanelProps {
  request: VerifierRequest | null;
  result: PolicyEvaluationResult | null;
  auditEntries: AuditLogEntry[];
  privacyConsent: PrivacyConsent | null;
  onOpenDataFlow: () => void;
}

function claimLabel(value: string): string {
  return value.replace(/_/g, ' ');
}

function StateBadge({ state }: { state: 'idle' | 'prompt' | 'approved' | 'denied' }) {
  const palette = {
    idle: { bg: '#e5e7eb', fg: '#374151', label: 'Idle' },
    prompt: { bg: '#fef3c7', fg: '#92400e', label: 'Consent prompt' },
    approved: { bg: '#dcfce7', fg: '#166534', label: 'Approved' },
    denied: { bg: '#fee2e2', fg: '#991b1b', label: 'Denied' },
  }[state];

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 10px',
        borderRadius: 999,
        background: palette.bg,
        color: palette.fg,
        fontSize: 12,
        fontWeight: 700,
      }}
    >
      {palette.label}
    </span>
  );
}

export function ConsentManagerPanel({
  request,
  result,
  auditEntries,
  privacyConsent,
  onOpenDataFlow,
}: ConsentManagerPanelProps) {
  const model = buildConsentManagerViewModel({
    request,
    result,
    auditEntries,
    privacyConsent,
  });

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
    </section>
  );
}

