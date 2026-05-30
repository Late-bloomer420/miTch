import './LandingPage.css';

type LandingPageProps = {
  onLaunchDemo: () => void;
};

const proofSteps = [
  { label: 'Verifier asks', value: 'age >= 18', state: 'request' },
  { label: 'Policy checks', value: 'ALLOW', state: 'allow' },
  { label: 'Wallet sends', value: 'proof only', state: 'proof' },
  { label: 'Session ends', value: 'key shredded', state: 'shred' },
];

const pillars = [
  {
    title: 'Fail-closed policy',
    body: 'Ambiguous requests resolve to DENY, with reason codes your compliance team can inspect.',
  },
  {
    title: 'Minimal disclosure',
    body: 'Verifiers receive predicates and signed presentations instead of names, birthdays, or addresses.',
  },
  {
    title: 'Audit-ready deletion',
    body: 'Decision capsules, WORM audit traces, and crypto-shredding produce evidence without retaining PII.',
  },
];

const useCases = ['Age checks', 'Healthcare access', 'Professional licenses', 'Student eligibility'];

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="landing-icon">
      <path d="M12 3l7 2.5v5.7c0 4.3-2.8 8.2-7 9.8-4.2-1.6-7-5.5-7-9.8V5.5L12 3z" />
      <path d="M9 12.1l2 2 4.2-4.5" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="arrow-icon">
      <path d="M5 12h13" />
      <path d="M13 6l6 6-6 6" />
    </svg>
  );
}

export function LandingPage({ onLaunchDemo }: LandingPageProps) {
  return (
    <main className="landing-page">
      <header className="landing-header">
        <a className="landing-brand" href="/" aria-label="miTch home">
          <span className="landing-brand-mark">m</span>
          <span>miTch</span>
        </a>
        <nav className="landing-nav" aria-label="Primary navigation">
          <a href="#platform">Platform</a>
          <a href="#compliance">Compliance</a>
          <a href="#use-cases">Use cases</a>
        </nav>
        <button className="landing-header-cta" type="button" onClick={onLaunchDemo}>
          Open demo
        </button>
      </header>

      <section className="landing-hero" id="platform">
        <div className="hero-copy">
          <h1>Verify the fact. Forget the data.</h1>
          <p>
            miTch is the privacy firewall for digital identity teams. Let wallets prove
            eligibility, role, age, or access rights while raw personal data stays off your
            servers.
          </p>
          <div className="hero-actions">
            <button className="hero-primary" type="button" onClick={onLaunchDemo}>
              Run the live proof
              <ArrowIcon />
            </button>
            <a className="hero-secondary" href="#compliance">
              See compliance posture
            </a>
          </div>
          <dl className="hero-metrics" aria-label="Project proof points">
            <div>
              <dt>28</dt>
              <dd>packages</dd>
            </div>
            <div>
              <dt>1664+</dt>
              <dd>tests</dd>
            </div>
            <div>
              <dt>0</dt>
              <dd>PII custody</dd>
            </div>
          </dl>
        </div>

        <div className="proof-console" aria-label="miTch proof flow preview">
          <div className="console-topbar">
            <span>Decision capsule</span>
            <strong>fail-closed</strong>
          </div>
          <div className="flow-line">
            {proofSteps.map((step, index) => (
              <div className={`flow-node flow-node--${step.state}`} key={step.label}>
                <span>{step.label}</span>
                <strong>{step.value}</strong>
                {index < proofSteps.length - 1 && <ArrowIcon />}
              </div>
            ))}
          </div>
          <div className="console-grid">
            <div className="console-panel console-panel--dark">
              <span>Requested</span>
              <strong>age, birthDate, address</strong>
            </div>
            <div className="console-panel console-panel--green">
              <span>Released</span>
              <strong>ageOver18: true</strong>
            </div>
            <div className="console-panel console-panel--red">
              <span>Blocked</span>
              <strong>birthDate, address</strong>
            </div>
          </div>
          <div className="audit-strip">
            <span>policy_hash: 7f2a...</span>
            <span>decision_id: dc_042</span>
            <span>ephemeral_key: destroyed</span>
          </div>
        </div>
      </section>

      <section className="pillar-section" aria-label="Core capabilities">
        {pillars.map((pillar) => (
          <article className="pillar-card" key={pillar.title}>
            <ShieldIcon />
            <h2>{pillar.title}</h2>
            <p>{pillar.body}</p>
          </article>
        ))}
      </section>

      <section className="compliance-section" id="compliance">
        <div>
          <h2>Built for regulated identity flows.</h2>
          <p>
            The platform aligns proof mediation, local wallet storage, encrypted presentations,
            and audit evidence with the constraints teams face under privacy-by-design regimes.
          </p>
        </div>
        <div className="compliance-list">
          <span>GDPR Art. 25</span>
          <span>eIDAS 2.0 / EUDI</span>
          <span>OID4VP + OID4VCI</span>
          <span>EHDS step-up</span>
        </div>
      </section>

      <section className="use-case-section" id="use-cases">
        <h2>One layer for every verifier that asks too much.</h2>
        <div className="use-case-rail">
          {useCases.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
      </section>

      <section className="final-cta">
        <h2>Turn the demo into your proof policy.</h2>
        <p>
          Start with the live wallet flow, then map your verifier requests to a deny-biased
          disclosure policy.
        </p>
        <button className="hero-primary" type="button" onClick={onLaunchDemo}>
          Open the wallet demo
          <ArrowIcon />
        </button>
      </section>
    </main>
  );
}
