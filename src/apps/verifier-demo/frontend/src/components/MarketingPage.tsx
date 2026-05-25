import React, { useState } from 'react';

export function MarketingPage() {
  const [activeFaq, setActiveFaq] = useState<number | null>(null);

  const faqs = [
    {
      q: 'Is miTch a wallet?',
      a: "No. miTch is a privacy-preserving firewall middleware. It intercepts verification queries, evaluates policy rules, and ensures the user's wallet only releases the cryptographic proof necessary, leaving the raw credential withheld.",
    },
    {
      q: 'Does miTch store identity data?',
      a: 'Never. miTch acts under a strict crypto-shredding, zero-custody architecture. Unused claims are completely withheld at the source. Audit events record only PII-minimal transaction markers (verification outcomes, cryptographic hashes) to prevent tracking.',
    },
    {
      q: 'What happens when policy is unclear?',
      a: 'miTch operates on a strict fail-closed security principle. If any jurisdiction scope, credential schema, or policy rule evaluates to ambiguous or undefined, the verdict defaults to DENY, preventing silent over-sharing.',
    },
    {
      q: 'How does auditability work?',
      a: 'Every transaction generates a signed DecisionCapsule containing validation states and a block reference. These are chained cryptographically to guarantee tamper-proof historical audits without leaking personal data.',
    },
  ];

  return (
    <div className="marketing-wrap">
      {/* 1. HERO SECTION */}
      <section className="hero-marketing">
        <div className="hero-marketing-copy">
          <span className="section-eyebrow">The Personal Trust Firewall</span>
          <h2>Prove only what is needed.</h2>
          <p>
            miTch is the privacy-preserving proof mediation layer ("The Forgetting Layer"). It
            sitting between identity wallets and verifiers to evaluate selective disclosure rules
            locally. Verifiers get cryptographic answers, while raw personal identifiers stay
            completely withheld.
          </p>
          <div className="hero-marketing-actions" style={{ display: 'flex', gap: '16px' }}>
            <a href="#playground" className="btn btn-primary">
              ⚡ Launch Interactive Playground
            </a>
            <a href="#dashboard" className="btn btn-secondary">
              📊 View Operational Metrics
            </a>
          </div>
          <div className="hero-marketing-meta">
            <span className="tag-pill">Selective Disclosure</span>
            <span className="tag-pill">Fail-Closed Policy</span>
            <span className="tag-pill">PQC-Agile Posture</span>
            <span className="tag-pill">GDPR Art. 25 + eIDAS 2.0</span>
          </div>
        </div>

        <div className="hero-interactive-concept glass-panel">
          <div style={{ padding: '36px', textAlign: 'center' }}>
            <div
              style={{
                fontSize: '3.5rem',
                marginBottom: '16px',
                filter: 'drop-shadow(0 0 15px rgba(101,214,232,0.3))',
              }}
            >
              🛡️
            </div>
            <h3 style={{ fontSize: '1.4rem', marginBottom: '12px', color: '#fff' }}>
              The miTch Disclosure firewall
            </h3>
            <p
              style={{
                color: 'var(--text-muted)',
                fontSize: '0.9rem',
                lineHeight: '1.6',
                marginBottom: '20px',
              }}
            >
              Standard transactions expose full certificates. miTch intercepts requests and
              generates selective proofs, reducing the attack surface to zero.
            </p>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '12px',
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.06)',
                padding: '10px 16px',
                borderRadius: 'var(--radius-sm)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                color: 'var(--accent)',
              }}
            >
              <span>JSON-LD Request</span>
              <span>➜</span>
              <span style={{ color: 'var(--accent-green)' }}>ZK Attribute Proof</span>
            </div>
          </div>
        </div>
      </section>

      {/* 2. PROBLEM VS SOLUTION */}
      <section className="band" id="problem" style={{ marginBottom: '96px' }}>
        <div className="section-headline">
          <span className="section-eyebrow">Exposure vs Mediation</span>
          <h3 className="section-title">Identity checks shouldn't become data leaks.</h3>
          <p className="section-desc">
            Most legacy digital checks still demand full copies of identity certificates, leaving
            sensitive records exposed.
          </p>
        </div>

        <div className="comparison-grid">
          <div className="comparison-card negative">
            <div className="comp-header">
              <span className="comp-icon">☠️</span>
              <div>
                <h4 style={{ color: 'var(--accent-red)' }}>Traditional KYC Flows</h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Over-collection by default
                </p>
              </div>
            </div>
            <div className="comp-list">
              <div className="comp-item">
                Full certificates (name, address, exact birthday) are permanently cached.
              </div>
              <div className="comp-item">
                Centralized data hoarding increases audit liability and breach risks.
              </div>
              <div className="comp-item">
                No ability to revoke or control downstream disclosure once shared.
              </div>
            </div>
          </div>

          <div className="comparison-card positive">
            <div className="comp-header">
              <span className="comp-icon">🛡️</span>
              <div>
                <h4 style={{ color: 'var(--accent-green)' }}>miTch Smart Mediation</h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  PII-Minimization by Design
                </p>
              </div>
            </div>
            <div className="comp-list">
              <div className="comp-item">
                Only the minimum boolean validation (e.g. isOver18) is generated.
              </div>
              <div className="comp-item">
                Raw credentials remain fully encrypted inside secure local storage.
              </div>
              <div className="comp-item">
                Fail-closed policy engine rejects unauthorized/incompatible verifier requests.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. STEPPER FLOW */}
      <section className="band" style={{ marginBottom: '96px' }}>
        <div className="section-headline">
          <span className="section-eyebrow">Protocol Pipeline</span>
          <h3 className="section-title">One query in. One selective proof out.</h3>
          <p className="section-desc">
            The selective disclosure pipeline processes transactions in milliseconds using
            high-performance cryptographic bindings.
          </p>
        </div>

        <div className="stepper-flow">
          <div className="stepper-card glass-panel">
            <div className="step-num">1</div>
            <h4>Verifier Request</h4>
            <p>Relying Party asks for claims via an OID4VP presentation challenge.</p>
          </div>
          <div className="stepper-card glass-panel">
            <div className="step-num">2</div>
            <h4>Policy Gate</h4>
            <p>miTch evaluates verifier jurisdiction, credential schema and revocations.</p>
          </div>
          <div className="stepper-card glass-panel">
            <div className="step-num">3</div>
            <h4>User Consent</h4>
            <p>Wallet reveals filtered claims, leaving sensitive metadata withheld.</p>
          </div>
          <div className="stepper-card glass-panel">
            <div className="step-num">4</div>
            <h4>ZKP Proof</h4>
            <p>Ephemerally signed SD-JWT VCs build a highly secure bound proof.</p>
          </div>
          <div className="stepper-card glass-panel">
            <div className="step-num">5</div>
            <h4>Audit Event</h4>
            <p>Minimum decision hash is written to the immutable verification trail.</p>
          </div>
        </div>
      </section>

      {/* 4. USE CASES */}
      <section className="band" style={{ marginBottom: '96px' }}>
        <div className="section-headline">
          <span className="section-eyebrow">Deployments</span>
          <h3 className="section-title">Where selective disclosure matters most.</h3>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: '20px',
          }}
        >
          <div className="glass-panel" style={{ padding: '24px' }}>
            <span style={{ fontSize: '2rem', marginBottom: '12px', display: 'block' }}>🍺</span>
            <h4 style={{ marginBottom: '8px' }}>Age Verification</h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Prove role and age eligibility (e.g. over 18) without disclosing exact birth date,
              legal name, or national registration ID.
            </p>
          </div>
          <div className="glass-panel" style={{ padding: '24px' }}>
            <span style={{ fontSize: '2rem', marginBottom: '12px', display: 'block' }}>🏥</span>
            <h4 style={{ marginBottom: '8px' }}>Medical Logins</h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Authenticate surgeon or specialist credentials, enabling ER access while concealing
              hospital payrolls or private contacts.
            </p>
          </div>
          <div className="glass-panel" style={{ padding: '24px' }}>
            <span style={{ fontSize: '2rem', marginBottom: '12px', display: 'block' }}>🚑</span>
            <h4 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>Emergency Care</h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Surface allergies and blood groups instantly to first-responders during emergency
              check-ins while keeping full histories masked.
            </p>
          </div>
          <div className="glass-panel" style={{ padding: '24px' }}>
            <span style={{ fontSize: '2rem', marginBottom: '12px', display: 'block' }}>💊</span>
            <h4 style={{ marginBottom: '8px' }}>E-Prescriptions</h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Validate active medication and refills at the counter without revealing auxiliary
              clinical diagnoses or insurance profiles.
            </p>
          </div>
        </div>
      </section>

      {/* 5. FAQs */}
      <section className="band" style={{ marginBottom: '96px' }}>
        <div className="section-headline">
          <span className="section-eyebrow">FAQ</span>
          <h3 className="section-title">Frequently Asked Questions</h3>
        </div>

        <div style={{ maxWidth: '800px', margin: '0 auto', display: 'grid', gap: '16px' }}>
          {faqs.map((faq, idx) => {
            const isOpen = activeFaq === idx;
            return (
              <div
                key={idx}
                className="glass-panel"
                style={{
                  padding: '20px',
                  cursor: 'pointer',
                  borderLeft: isOpen ? '3px solid var(--accent)' : '1px solid var(--border)',
                }}
                onClick={() => setActiveFaq(isOpen ? null : idx)}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    fontWeight: 700,
                  }}
                >
                  <h4
                    style={{ fontSize: '1.05rem', color: isOpen ? 'var(--accent)' : 'var(--text)' }}
                  >
                    {faq.q}
                  </h4>
                  <span style={{ color: 'var(--accent)', fontSize: '1.2rem' }}>
                    {isOpen ? '−' : '+'}
                  </span>
                </div>
                {isOpen && (
                  <p
                    style={{
                      marginTop: '12px',
                      fontSize: '0.9rem',
                      color: 'var(--text-muted)',
                      lineHeight: '1.6',
                    }}
                  >
                    {faq.a}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
