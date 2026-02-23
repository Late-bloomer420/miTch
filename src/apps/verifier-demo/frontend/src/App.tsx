import { useEffect, useState } from 'react';
import QRCode from 'react-qr-code';
import './App.css';

type VerificationStatus = 'WAITING' | 'VERIFIED' | 'FAILED';

const STATUS_COPY: Record<VerificationStatus, { badge: string; title: string; subtitle: string }> = {
    WAITING: {
        badge: 'WAITING',
        title: 'Waiting for customer',
        subtitle: 'Scan QR to prove: Age >= 18 (ZK predicate).'
    },
    VERIFIED: {
        badge: 'VERIFIED',
        title: 'Age verified',
        subtitle: 'Predicate satisfied: age >= 18.'
    },
    FAILED: {
        badge: 'DENIED',
        title: 'Access denied',
        subtitle: 'Denied by policy (fail-closed).'
    }
};

export default function App() {
    const [status, setStatus] = useState<VerificationStatus>('WAITING');
    const [verifierDid, setVerifierDid] = useState<string>('');
    const [trustedIssuer, setTrustedIssuer] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<string>('');
    const [qrPayload, setQrPayload] = useState<string>('');

    useEffect(() => {
        const fetchIdentity = async () => {
            try {
                const res = await fetch('/api/did.json');
                const didDoc = await res.json();

                const request = {
                    verifierId: didDoc.id,
                    origin: window.location.origin,
                    purpose: 'Verify age is 18+ for alcohol purchase',
                    requirements: [{
                        credentialType: 'AgeCredential',
                        requestedProvenClaims: ['age >= 18'],
                        issuerTrustRefs: ['did:mitch:gov-id-issuer']
                    }],
                    nonce: crypto.randomUUID(),
                    serviceEndpoint: didDoc.service?.[0]?.serviceEndpoint || 'http://localhost:3002/present'
                };

                setQrPayload(JSON.stringify(request));
            } catch (e) {
                console.error('Failed to load verifier identity', e);
            }
        };

        if (!qrPayload) fetchIdentity();

        const interval = setInterval(async () => {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();

                if (data.status !== status) {
                    setStatus(data.status);
                    setTrustedIssuer(data.issuer);
                    setLastUpdated(new Date().toLocaleTimeString());
                }
                setVerifierDid(data.verifierDid);
            } catch (error) {
                console.error('Failed to fetch status:', error);
            }
        }, 1000);

        return () => clearInterval(interval);
    }, [status, qrPayload]);

    const handleReset = async () => {
        await fetch('/api/reset', { method: 'POST' });
        setStatus('WAITING');
    };

    const copy = STATUS_COPY[status];
    const issuerLabel = trustedIssuer || 'Unknown trusted issuer';
    const didLabel = verifierDid || 'loading...';

    return (
        <div className="proof-console">
            <div className="ambient-grid" aria-hidden="true" />

            <header className="console-header">
                <div className="brand">
                    <div className="brand-mark">mi</div>
                    <div>
                        <p className="brand-title">Demo Liquor Store</p>
                        <p className="brand-subtitle">Proof Console</p>
                    </div>
                </div>
                <div className="header-meta">
                    <span className="meta-label">Verifier DID</span>
                    <span className="meta-value">{didLabel}</span>
                </div>
            </header>

            <main className="console-main">
                <section className={`hero-card status-${status.toLowerCase()}`}>
                    <div className="status-badge">STATUS - {copy.badge}</div>
                    <h1 className="status-title">{copy.title}</h1>
                    <p className="status-subtitle">{copy.subtitle}</p>

                    {status === 'WAITING' && (
                        <div className="waiting-block">
                            <div className="qr-frame" aria-label="Verification QR">
                                <div className="qr-inner">
                                    {qrPayload ? (
                                        <QRCode value={qrPayload} size={220} bgColor="#ffffff" fgColor="#202124" />
                                    ) : (
                                        <div className="qr-placeholder">Preparing QR...</div>
                                    )}
                                </div>
                            </div>
                            <p className="waiting-copy">
                                This verifier receives proof only. No identity is stored. Prove age and forget.
                            </p>
                        </div>
                    )}

                    {status === 'VERIFIED' && (
                        <div className="proof-capsule">
                            <div className="capsule-row">
                                <span className="capsule-label">Result</span>
                                <span className="capsule-value">age &gt;= 18 (verified)</span>
                            </div>
                            <div className="capsule-row">
                                <span className="capsule-label">Issuer</span>
                                <span className="capsule-value mono">{issuerLabel}</span>
                            </div>
                            <div className="capsule-row">
                                <span className="capsule-label">Disclosed</span>
                                <span className="capsule-value">0 attributes</span>
                            </div>
                            <div className="capsule-row">
                                <span className="capsule-label">Ephemeral keys</span>
                                <span className="capsule-value">shredded</span>
                            </div>
                        </div>
                    )}

                    {status === 'FAILED' && (
                        <div className="denied-block">
                            <p className="denied-reason">Reason: under 18 or verification ambiguous.</p>
                            <div className="denied-card">
                                <p className="denied-title">What we did not learn</p>
                                <ul className="denied-list">
                                    <li>No identity revealed</li>
                                    <li>No credential stored</li>
                                    <li>No partial data retained</li>
                                </ul>
                            </div>
                        </div>
                    )}

                    <div className="chip-row">
                        <span className="chip">Policy: deny-by-default</span>
                        <span className="chip">Data: 0 disclosed</span>
                        <span className="chip">Retention: 0s</span>
                    </div>

                    <div className="event-row">
                        <span>Last event</span>
                        <span className="mono">{lastUpdated || '--:--:--'}</span>
                    </div>
                </section>

                <aside className="side-panel">
                    <div className="panel-card">
                        <h2>Proof Console</h2>
                        <p>
                            Requests are evaluated locally. The verifier sees a proof state, not personal data.
                        </p>
                        <div className="panel-grid">
                            <div>
                                <span className="panel-label">Mode</span>
                                <span className="panel-value">Fail-closed</span>
                            </div>
                            <div>
                                <span className="panel-label">Storage</span>
                                <span className="panel-value">Hash-only audit</span>
                            </div>
                            <div>
                                <span className="panel-label">Disclosure</span>
                                <span className="panel-value">Predicate only</span>
                            </div>
                            <div>
                                <span className="panel-label">Retention</span>
                                <span className="panel-value">0 seconds</span>
                            </div>
                        </div>
                    </div>

                    <div className="panel-card">
                        <h2>Security signals</h2>
                        <div className="signal-list">
                            <div className="signal-item">
                                <span className="signal-dot" />
                                <span>Request: signed</span>
                            </div>
                            <div className="signal-item">
                                <span className="signal-dot" />
                                <span>Nonce: present</span>
                            </div>
                            <div className="signal-item">
                                <span className="signal-dot" />
                                <span>Replay: blocked</span>
                            </div>
                            <div className="signal-item">
                                <span className="signal-dot" />
                                <span>Audit: hash-only</span>
                            </div>
                        </div>
                    </div>
                </aside>
            </main>

            <footer className="console-footer">
                <div className="footer-left">
                    Powered by <span>miTch</span> Privacy-by-Architecture
                </div>
                <div className="footer-actions">
                    <button onClick={handleReset} className="reset-btn">
                        Reset for next customer
                    </button>
                </div>
            </footer>
        </div>
    );
}
