import React, { useState } from 'react';
import { SCENARIOS, SCENARIO_ORDER } from '../data/scenarios';
import type { ScenarioId } from '../data/scenarios';

interface ConsentReceipt {
  purpose?: string;
  scope?: Record<string, unknown>;
  timestamp: string;
}

interface AuditEntry {
  correlationId?: string;
  outcome?: string;
  decisionDigest?: string;
  timestamp: string;
}

interface PlaygroundProps {
  backendUrl: string;
  onPresented: () => void;
}

type FlowState = 'idle' | 'consent' | 'presenting' | 'done' | 'denied' | 'error';

export function Playground({ backendUrl, onPresented }: PlaygroundProps) {
  const [selectedId, setSelectedId] = useState<ScenarioId>('liquor-store');
  const [flowState, setFlowState] = useState<FlowState>('idle');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Ephemeral transaction payload received from backend E2E verification
  const [disclosedClaims, setDisclosedClaims] = useState<Record<string, unknown> | null>(null);
  const [consentReceipt, setConsentReceipt] = useState<ConsentReceipt | null>(null);
  const [auditEntry, setAuditEntry] = useState<AuditEntry | null>(null);

  const scenario = SCENARIOS[selectedId];

  const handleScenarioChange = (id: ScenarioId) => {
    setSelectedId(id);
    handleReset();
  };

  const handlePresent = () => {
    setFlowState('consent');
  };

  const handleConsent = async () => {
    setFlowState('presenting');
    setErrorMsg(null);
    try {
      const res = await fetch(`${backendUrl}/wallet-present`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId: scenario.id }),
      });
      const data = (await res.json()) as {
        ok: boolean;
        errors?: string[];
        error?: string;
        disclosedClaims?: Record<string, unknown>;
        consentReceipt?: ConsentReceipt;
        auditEntry?: AuditEntry;
      };

      if (data.ok) {
        setDisclosedClaims(data.disclosedClaims ?? null);
        setConsentReceipt(data.consentReceipt ?? null);
        setAuditEntry(data.auditEntry ?? null);
        setFlowState('done');
        onPresented(); // Signal dashboard to reload stats!
      } else {
        setFlowState('denied');
        setErrorMsg(
          (data.errors ?? [data.error ?? 'Verification rejected by policy rules']).join(', ')
        );
        setDisclosedClaims(null);
        setConsentReceipt(data.consentReceipt ?? null);
        setAuditEntry(data.auditEntry ?? null);
        onPresented();
      }
    } catch (e: unknown) {
      setFlowState('error');
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setDisclosedClaims(null);
      setConsentReceipt(null);
      setAuditEntry(null);
    }
  };

  const handleReset = () => {
    setFlowState('idle');
    setErrorMsg(null);
    setDisclosedClaims(null);
    setConsentReceipt(null);
    setAuditEntry(null);
  };

  return (
    <section className="playground-section" id="playground">
      <div className="section-headline">
        <span className="section-eyebrow">Interactive Playfield</span>
        <h3 className="section-title">Selective Disclosure Laboratory</h3>
        <p className="section-desc">
          Test real-time selective disclosure and fail-closed policies. Select a scenario on the
          simulated wallet, present credentials, and analyze what the verifier receives.
        </p>
      </div>

      <div className="playground-grid">
        {/* LEFT COLUMN: Simulated Wallet Device (Mock Phone) */}
        <div className="phone-mockup">
          <div className="phone-notch"></div>
          <div className="phone-screen">
            <div className="phone-header">
              <span className="phone-title">📱 miTch Wallet</span>
              <span
                className="phone-badge"
                style={{
                  background:
                    flowState === 'consent'
                      ? 'rgba(243, 177, 95, 0.1)'
                      : flowState === 'done'
                        ? 'rgba(154, 212, 180, 0.1)'
                        : flowState === 'denied' || flowState === 'error'
                          ? 'rgba(242, 108, 108, 0.1)'
                          : 'rgba(101, 214, 232, 0.1)',
                  borderColor:
                    flowState === 'consent'
                      ? 'var(--accent-gold)'
                      : flowState === 'done'
                        ? 'var(--accent-green)'
                        : flowState === 'denied' || flowState === 'error'
                          ? 'var(--accent-red)'
                          : 'var(--accent)',
                  color:
                    flowState === 'consent'
                      ? 'var(--accent-gold)'
                      : flowState === 'done'
                        ? 'var(--accent-green)'
                        : flowState === 'denied' || flowState === 'error'
                          ? 'var(--accent-red)'
                          : 'var(--accent)',
                }}
              >
                {flowState === 'consent'
                  ? 'Consent Prompt'
                  : flowState === 'presenting'
                    ? 'Presenting'
                    : flowState === 'done'
                      ? 'Success'
                      : flowState === 'denied' || flowState === 'error'
                        ? 'Blocked'
                        : 'Active'}
              </span>
            </div>

            {flowState === 'consent' ? (
              /* ==================== HIGH FIDELITY CONSENT MANAGER VIEW ==================== */
              <div
                className="phone-consent-manager"
                style={{
                  flex: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px',
                  paddingBottom: '4px',
                  overflowY: 'auto',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    textAlign: 'center',
                    borderBottom: '1px solid rgba(255,255,255,0.06)',
                    paddingBottom: '12px',
                  }}
                >
                  <div style={{ fontSize: '1.8rem', marginBottom: '4px' }}>🛡️</div>
                  <h4
                    style={{
                      fontSize: '0.95rem',
                      fontWeight: 700,
                      color: '#fff',
                      fontFamily: 'var(--font-display)',
                    }}
                  >
                    miTch Consent Manager
                  </h4>
                  <span
                    style={{
                      fontSize: '0.62rem',
                      letterSpacing: '0.05em',
                      textTransform: 'uppercase',
                      background: 'rgba(243, 177, 95, 0.1)',
                      border: '1px solid var(--accent-gold)',
                      color: 'var(--accent-gold)',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-pill)',
                      marginTop: '6px',
                      fontWeight: 800,
                    }}
                  >
                    GDPR Art. 25 Firewall Prompt
                  </span>
                </div>

                <div
                  style={{
                    fontSize: '0.72rem',
                    lineHeight: '1.4',
                    background: 'rgba(255,255,255,0.02)',
                    padding: '10px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid rgba(255,255,255,0.04)',
                  }}
                >
                  <strong style={{ color: 'var(--text-muted)' }}>Verifier Request:</strong>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      marginTop: '6px',
                      color: '#fff',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                    }}
                  >
                    <span>{scenario.emoji}</span>
                    <span>{scenario.label}</span>
                  </div>
                  <div
                    style={{
                      fontSize: '0.65rem',
                      color: 'var(--text-muted)',
                      marginTop: '2px',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    did:mitch:verifier-{scenario.id}
                  </div>
                </div>

                {/* Minimization Metrics */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                  <div
                    style={{
                      background: 'rgba(255,255,255,0.01)',
                      border: '1px solid rgba(255,255,255,0.03)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '6px 8px',
                      textAlign: 'center',
                    }}
                  >
                    <span
                      style={{
                        fontSize: '0.55rem',
                        color: 'var(--text-muted)',
                        display: 'block',
                        textTransform: 'uppercase',
                      }}
                    >
                      Minimization
                    </span>
                    <strong style={{ fontSize: '0.7rem', color: 'var(--accent-green)' }}>
                      {scenario.id === 'liquor-store' ? 'ZKP Predicate' : 'Selective (SD)'}
                    </strong>
                  </div>
                  <div
                    style={{
                      background: 'rgba(255,255,255,0.01)',
                      border: '1px solid rgba(255,255,255,0.03)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '6px 8px',
                      textAlign: 'center',
                    }}
                  >
                    <span
                      style={{
                        fontSize: '0.55rem',
                        color: 'var(--text-muted)',
                        display: 'block',
                        textTransform: 'uppercase',
                      }}
                    >
                      Linkability
                    </span>
                    <strong style={{ fontSize: '0.7rem', color: 'var(--accent)' }}>
                      Unlinkable
                    </strong>
                  </div>
                </div>

                {/* Grid layout of Requested, Allowed, Withheld */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1 }}>
                  {/* Requested Claims */}
                  <div
                    style={{
                      background: 'rgba(101, 214, 232, 0.02)',
                      border: '1px solid rgba(101, 214, 232, 0.12)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px',
                    }}
                  >
                    <h5
                      style={{
                        fontSize: '0.7rem',
                        color: 'var(--accent)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: '6px',
                        fontWeight: 800,
                      }}
                    >
                      Requested Claims
                    </h5>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {scenario.walletCredentials
                        .flatMap((c) => c.fields)
                        .map((f) => (
                          <span
                            key={f.key}
                            style={{
                              fontSize: '0.6rem',
                              background: 'rgba(101, 214, 232, 0.08)',
                              color: 'var(--accent)',
                              border: '1px solid rgba(101, 214, 232, 0.15)',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          >
                            {f.key}
                          </span>
                        ))}
                    </div>
                  </div>

                  {/* Allowed / Disclosed Claims */}
                  <div
                    style={{
                      background: 'rgba(154, 212, 180, 0.02)',
                      border: '1px solid rgba(154, 212, 180, 0.12)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px',
                    }}
                  >
                    <h5
                      style={{
                        fontSize: '0.7rem',
                        color: 'var(--accent-green)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: '6px',
                        fontWeight: 800,
                      }}
                    >
                      Disclosed / Proven
                    </h5>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {scenario.verifierReceives.map((c) => (
                        <span
                          key={c.key}
                          style={{
                            fontSize: '0.6rem',
                            background: 'rgba(154, 212, 180, 0.08)',
                            color: 'var(--accent-green)',
                            border: '1px solid rgba(154, 212, 180, 0.15)',
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontFamily: 'var(--font-mono)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '3px',
                          }}
                        >
                          ✓ {c.key}{' '}
                          {c.isProof && (
                            <span
                              style={{
                                fontSize: '0.5rem',
                                background: 'rgba(154, 212, 180, 0.2)',
                                padding: '0px 3px',
                                borderRadius: '2px',
                                fontWeight: 800,
                              }}
                            >
                              ZKP
                            </span>
                          )}
                        </span>
                      ))}
                      {scenario.verifierReceives.length === 0 && (
                        <span
                          style={{
                            fontSize: '0.65rem',
                            color: 'var(--accent-red)',
                            fontWeight: 600,
                          }}
                        >
                          🚫 None (Fail-Closed Deny)
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Withheld / Redacted Claims */}
                  <div
                    style={{
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid rgba(255, 255, 255, 0.06)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px',
                    }}
                  >
                    <h5
                      style={{
                        fontSize: '0.7rem',
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: '6px',
                        fontWeight: 800,
                      }}
                    >
                      Withheld / Redacted
                    </h5>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {scenario.blocked.map((b) => (
                        <span
                          key={b}
                          style={{
                            fontSize: '0.6rem',
                            background: 'rgba(255,255,255,0.03)',
                            color: 'var(--text-muted)',
                            border: '1px solid rgba(255,255,255,0.05)',
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontFamily: 'var(--font-mono)',
                            textDecoration: 'line-through',
                          }}
                        >
                          {b} [withheld]
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Identity & Privacy Signals */}
                  <div
                    style={{
                      background: 'rgba(182, 137, 255, 0.02)',
                      border: '1px solid rgba(182, 137, 255, 0.12)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px',
                    }}
                  >
                    <h5
                      style={{
                        fontSize: '0.7rem',
                        color: '#b689ff',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: '6px',
                        fontWeight: 800,
                      }}
                    >
                      Privacy & Identity Signals
                    </h5>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      <span
                        style={{
                          fontSize: '0.6rem',
                          background: 'rgba(182, 137, 255, 0.08)',
                          color: '#b689ff',
                          border: '1px solid rgba(182, 137, 255, 0.15)',
                          padding: '2px 6px',
                          borderRadius: '4px',
                        }}
                      >
                        🛡️ Holder Key-Binding
                      </span>
                      <span
                        style={{
                          fontSize: '0.6rem',
                          background: 'rgba(182, 137, 255, 0.08)',
                          color: '#b689ff',
                          border: '1px solid rgba(182, 137, 255, 0.15)',
                          padding: '2px 6px',
                          borderRadius: '4px',
                        }}
                      >
                        🔑 Pairwise DID (did:key)
                      </span>
                      {scenario.id === 'liquor-store' && (
                        <span
                          style={{
                            fontSize: '0.6rem',
                            background: 'rgba(182, 137, 255, 0.08)',
                            color: '#b689ff',
                            border: '1px solid rgba(182, 137, 255, 0.15)',
                            padding: '2px 6px',
                            borderRadius: '4px',
                          }}
                        >
                          🙈 Zero-Knowledge Proof
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Consent Actions */}
                <div
                  style={{
                    display: 'flex',
                    gap: '8px',
                    marginTop: 'auto',
                    paddingTop: '10px',
                    borderTop: '1px solid rgba(255,255,255,0.06)',
                  }}
                >
                  <button
                    className="btn btn-primary"
                    onClick={handleConsent}
                    style={{
                      flex: 1.2,
                      padding: '10px 0',
                      fontSize: '0.75rem',
                      background: 'linear-gradient(135deg, var(--accent-green) 0%, #7ec29e 100%)',
                      color: '#071018',
                      border: 'none',
                      fontWeight: 800,
                    }}
                  >
                    Authorize & Sign Proof
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={handleReset}
                    style={{
                      flex: 0.8,
                      padding: '10px 0',
                      fontSize: '0.75rem',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      color: 'var(--text-muted)',
                    }}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ) : (
              /* ==================== STANDARD WALLET VIEW ==================== */
              <>
                {/* Horizontal Scenario Selector inside screen */}
                <div className="scenario-selector">
                  {SCENARIO_ORDER.map((id) => {
                    const s = SCENARIOS[id];
                    const isActive = id === selectedId;
                    return (
                      <button
                        key={id}
                        className={`scenario-tab ${isActive ? 'active' : ''}`}
                        onClick={() => handleScenarioChange(id)}
                        title={s.label}
                      >
                        <span className="scenario-emoji">{s.emoji}</span>
                        <span className="scenario-lbl">{s.label}</span>
                      </button>
                    );
                  })}
                </div>

                {/* Credential Listing */}
                <div style={{ flex: 1, overflowY: 'auto', paddingBottom: '16px' }}>
                  <div
                    style={{
                      fontSize: '0.7rem',
                      color: 'var(--accent)',
                      fontWeight: 800,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      marginBottom: '10px',
                    }}
                  >
                    Available Credentials
                  </div>

                  {scenario.walletCredentials.map((cred, idx) => (
                    <div
                      key={idx}
                      className={`credential-card ${flowState === 'done' ? 'verified' : ''}`}
                    >
                      <div className="cred-title">{cred.type}</div>
                      <div className="cred-issuer">{cred.issuer}</div>

                      {cred.fields.map((field) => {
                        const isRedacted = flowState !== 'idle' && field.blocked;
                        return (
                          <div
                            key={field.key}
                            className={`cred-field ${isRedacted ? 'redacted' : ''}`}
                          >
                            <span className="cred-key">{field.key}</span>
                            <span className="cred-val">
                              {isRedacted ? '[withheld]' : field.value}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>

                {/* Phone Screen Action Layer */}
                <div style={{ marginTop: 'auto' }}>
                  {flowState === 'idle' && (
                    <button
                      className="btn btn-primary"
                      onClick={handlePresent}
                      style={{ width: '100%' }}
                    >
                      Present Proof ➔
                    </button>
                  )}

                  {flowState === 'presenting' && (
                    <div
                      style={{
                        textAlign: 'center',
                        padding: '16px',
                        background: 'rgba(0,0,0,0.4)',
                        borderRadius: 'var(--radius-md)',
                      }}
                    >
                      <div
                        style={{
                          color: 'var(--accent)',
                          fontSize: '0.85rem',
                          fontWeight: 600,
                          marginBottom: '6px',
                        }}
                      >
                        ⚡ Generating Cryptographic Proof...
                      </div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                        SD-JWT VC + KB-JWT Nonce Sign
                      </div>
                    </div>
                  )}

                  {flowState === 'done' && (
                    <div
                      style={{
                        padding: '16px',
                        background: 'rgba(154, 212, 180, 0.08)',
                        border: '1px solid var(--accent-green)',
                        borderRadius: 'var(--radius-md)',
                      }}
                    >
                      <div
                        style={{
                          color: 'var(--accent-green)',
                          fontSize: '0.85rem',
                          fontWeight: 700,
                          marginBottom: '4px',
                        }}
                      >
                        ✓ Proof Transmitted
                      </div>
                      <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        SD-JWT presentation envelope cryptographically validated.
                      </p>
                      <button
                        className="btn btn-secondary"
                        onClick={handleReset}
                        style={{
                          marginTop: '10px',
                          width: '100%',
                          padding: '6px 0',
                          fontSize: '0.75rem',
                        }}
                      >
                        Reset Demo
                      </button>
                    </div>
                  )}

                  {(flowState === 'denied' || flowState === 'error') && (
                    <div
                      style={{
                        padding: '16px',
                        background: 'rgba(242, 108, 108, 0.08)',
                        border: '1px solid var(--accent-red)',
                        borderRadius: 'var(--radius-md)',
                      }}
                    >
                      <div
                        style={{
                          color: 'var(--accent-red)',
                          fontSize: '0.85rem',
                          fontWeight: 700,
                          marginBottom: '4px',
                        }}
                      >
                        {flowState === 'denied' ? '⛔ Verification Blocked' : '⚠ System Fault'}
                      </div>
                      <p
                        style={{
                          fontSize: '0.7rem',
                          color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {errorMsg || 'Fail-closed execution default to Deny.'}
                      </p>
                      <button
                        className="btn btn-secondary"
                        onClick={handleReset}
                        style={{
                          marginTop: '10px',
                          width: '100%',
                          padding: '6px 0',
                          fontSize: '0.75rem',
                        }}
                      >
                        Reset Demo
                      </button>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Interactive Laboratory Console (Verifier Receipt) */}
        <div className="laboratory-panels">
          <div className="glass-panel receipt-card">
            <div className="receipt-header">
              <h3 className="receipt-title">🏪 Verifier Verification Report</h3>
              {flowState === 'done' && (
                <span className="receipt-status-pill allow">Verdict: ALLOW</span>
              )}
              {flowState === 'denied' && (
                <span className="receipt-status-pill deny">Verdict: DENY</span>
              )}
              {flowState !== 'done' && flowState !== 'denied' && (
                <span
                  className="receipt-status-pill"
                  style={{
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    color: 'var(--text-muted)',
                  }}
                >
                  Waiting
                </span>
              )}
            </div>

            {/* Interactive display showing what verifier gets */}
            <div style={{ display: 'grid', gap: '20px', marginBottom: '24px' }}>
              <div>
                <span
                  style={{
                    fontSize: '0.8rem',
                    textTransform: 'uppercase',
                    color: 'var(--text-muted)',
                    letterSpacing: '0.05em',
                    display: 'block',
                    marginBottom: '8px',
                  }}
                >
                  Decrypted Claims Payload
                </span>

                {disclosedClaims ? (
                  <pre className="payload-console">{JSON.stringify(disclosedClaims, null, 2)}</pre>
                ) : errorMsg ? (
                  <div className="payload-console" style={{ color: 'var(--accent-red)' }}>
                    [REJECTED] {errorMsg}
                  </div>
                ) : (
                  <div
                    className="payload-console"
                    style={{ fontStyle: 'italic', color: 'rgba(255,255,255,0.15)' }}
                  >
                    // Waiting for wallet credential presentation...
                  </div>
                )}
              </div>

              {/* Protocol Details & Receipts */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                {/* Consent & Minimization Receipt */}
                <div
                  style={{
                    background: 'rgba(255,255,255,0.01)',
                    border: '1px solid rgba(255,255,255,0.03)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '16px',
                  }}
                >
                  <h4
                    style={{
                      fontSize: '0.85rem',
                      color: '#fff',
                      marginBottom: '12px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    📄 Disclosure Consent Receipt
                  </h4>

                  {consentReceipt ? (
                    <div
                      style={{
                        display: 'grid',
                        gap: '8px',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Purpose:</span>{' '}
                        {consentReceipt.purpose}
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Minimization:</span> 100%
                        compliant
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Verifier Scope:</span>{' '}
                        {consentReceipt.scope ? JSON.stringify(consentReceipt.scope) : 'N/A'}
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Auth Time:</span>{' '}
                        {new Date(consentReceipt.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ) : (
                    <p
                      style={{
                        fontSize: '0.75rem',
                        color: 'rgba(255,255,255,0.1)',
                        fontStyle: 'italic',
                      }}
                    >
                      Pending presentation...
                    </p>
                  )}
                </div>

                {/* Secure Audit Trail event entry */}
                <div
                  style={{
                    background: 'rgba(255,255,255,0.01)',
                    border: '1px solid rgba(255,255,255,0.03)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '16px',
                  }}
                >
                  <h4
                    style={{
                      fontSize: '0.85rem',
                      color: '#fff',
                      marginBottom: '12px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    🔗 Crypto-Anchor Audit Trail
                  </h4>

                  {auditEntry ? (
                    <div
                      style={{
                        display: 'grid',
                        gap: '8px',
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      <div
                        style={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        <span style={{ color: 'var(--text-muted)' }}>Corr ID:</span>{' '}
                        {auditEntry.correlationId ?? 'N/A'}
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Outcome:</span>
                        <span
                          style={{
                            marginLeft: '4px',
                            fontWeight: 'bold',
                            color:
                              auditEntry.outcome === 'SUCCESS'
                                ? 'var(--accent-green)'
                                : 'var(--accent-red)',
                          }}
                        >
                          {auditEntry.outcome}
                        </span>
                      </div>
                      <div
                        style={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        <span style={{ color: 'var(--text-muted)' }}>Digest:</span>{' '}
                        {auditEntry.decisionDigest ?? 'aqdr:pending'}
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Timestamp:</span>{' '}
                        {new Date(auditEntry.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ) : (
                    <p
                      style={{
                        fontSize: '0.75rem',
                        color: 'rgba(255,255,255,0.1)',
                        fontStyle: 'italic',
                      }}
                    >
                      Pending presentation...
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div
              style={{
                borderTop: '1px solid rgba(255,255,255,0.05)',
                paddingTop: '16px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                fontSize: '0.75rem',
                color: 'var(--text-muted)',
              }}
            >
              <span>
                DID Controller:{' '}
                <strong style={{ color: 'var(--accent)' }}>did:mitch:verifier-liquor-store</strong>
              </span>
              <span>
                Endpoint: <strong style={{ color: '#fff' }}>/present</strong>
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
