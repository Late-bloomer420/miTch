import React, { useState } from 'react';
import { MarketingPage } from './components/MarketingPage';
import { Playground } from './components/Playground';
import { TelemetryDashboard } from './components/TelemetryDashboard';
import './App.css';

// Derive backend URL dynamically from location host for seamless localhost/LAN access
const backendUrl = `http://${window.location.hostname}:3004`;

export default function App() {
  // A refresh counter triggered when credentials are presented to update the telemetry stats in real-time
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handlePresented = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  return (
    <div className="portal-container">
      {/* Dynamic ambient grid background */}
      <div className="ambient-grid"></div>

      {/* TOPBAR BRAND HEADER */}
      <header
        className="portal-header glass-panel"
        style={{ padding: '16px 24px', margin: '24px 0 64px' }}
      >
        <div className="header-brand">
          <div className="brand-icon">🛡️</div>
          <div className="brand-text">
            <h1>miTch</h1>
            <span>The Forgetting Layer</span>
          </div>
        </div>
        <nav className="header-nav">
          <a href="#problem" className="nav-link">
            Privacy Firewall
          </a>
          <a href="#playground" className="nav-link">
            Laboratory PWA
          </a>
          <a href="#dashboard" className="nav-link">
            Live Telemetry
          </a>
          <a
            href="#playground"
            className="btn btn-primary nav-cta"
            style={{ fontSize: '0.8rem', padding: '8px 18px' }}
          >
            Open Demo ➔
          </a>
        </nav>
      </header>

      {/* MAIN SINGLE-PAGE SHOWCASE ROUTING */}
      <main>
        {/* Part 1: Immersive Hero, ICP Targets, Steppers & FAQ Accordion */}
        <MarketingPage />

        {/* Part 2: Interactive Selective Disclosure Mobile Simulation & Receipt Console */}
        <Playground backendUrl={backendUrl} onPresented={handlePresented} />

        {/* Part 3: Operational Dashboard, Active Denies, ROI Savings, Audit Trail & Quick-Ops */}
        <TelemetryDashboard backendUrl={backendUrl} refreshTrigger={refreshTrigger} />
      </main>

      {/* FOOTER */}
      <footer
        style={{
          marginTop: '96px',
          paddingTop: '24px',
          borderTop: '1px solid rgba(255,255,255,0.05)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.8rem',
          color: 'var(--text-muted)',
        }}
      >
        <span>
          © 2026 miTch — Personal Trust Hub & Showcase Portal. GDPR Art. 25 + eIDAS 2.0 Compliance.
        </span>
        <span>
          Live Sandbox:{' '}
          <a
            href="https://late-bloomer420.github.io/miTch/"
            target="_blank"
            rel="noreferrer"
            style={{ color: 'var(--accent)' }}
          >
            github.io/miTch
          </a>
        </span>
      </footer>
    </div>
  );
}
