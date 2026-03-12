import { useState, useEffect, useRef } from 'react';
import QRCode from 'react-qr-code';
import type { ScenarioDefinition } from '../data/scenarios';

interface StatusResponse {
    status: 'WAITING' | 'VERIFIED' | 'FAILED';
    issuer?: string;
    verifierDid?: string;
    disclosedClaims?: Record<string, unknown>;
    consentReceipt?: { id: string; claimsShared: string[]; purpose: string; timestamp: string };
}

interface VerifierPanelProps {
    scenario: ScenarioDefinition;
    backendUrl: string;
    runNonce: number;
}

export function VerifierPanel({ scenario, backendUrl, runNonce }: VerifierPanelProps) {
    const [panelState, setPanelState] = useState<'waiting' | 'verified' | 'failed' | 'offline'>('waiting');
    const [statusData, setStatusData] = useState<StatusResponse | null>(null);
    const lastRunNonce = useRef<number>(runNonce);

    // Reset when runNonce changes
    useEffect(() => {
        lastRunNonce.current = runNonce;
        setPanelState('waiting');
        setStatusData(null);
    }, [runNonce]);

    // Poll /status
    useEffect(() => {
        let errorCount = 0;
        const MAX_CONSECUTIVE_ERRORS = 3;

        const poll = async () => {
            try {
                const res = await fetch(`${backendUrl}/status`);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json() as StatusResponse;
                errorCount = 0;

                if (data.status === 'VERIFIED') {
                    setStatusData(data);
                    setPanelState('verified');
                } else if (data.status === 'FAILED') {
                    setStatusData(data);
                    setPanelState('failed');
                }
            } catch {
                errorCount++;
                if (errorCount >= MAX_CONSECUTIVE_ERRORS) setPanelState('offline');
            }
        };

        const intervalId = setInterval(poll, 1200);
        poll();
        return () => clearInterval(intervalId);
    }, [backendUrl, runNonce]);

    // --- WAITING ---
    if (panelState === 'waiting') {
        const walletBaseUrl = (import.meta as unknown as Record<string, Record<string, string>>).env?.VITE_WALLET_URL ?? 'http://localhost:5174';
        const walletDeepLink = `${walletBaseUrl}/?scenario=${scenario.id}&endpoint=${encodeURIComponent(backendUrl)}&verifier=did%3Amitch%3Averifier-liquor-store`;
        return (
            <div style={{ textAlign: 'center', padding: 24 }}>
                <QRCode
                    value={walletDeepLink}
                    size={160}
                    bgColor="#ffffff"
                    fgColor="#0a0a0a"
                />
                <div style={{ marginTop: 12, color: '#555', fontSize: 13 }}>
                    ● Scan with wallet or open link below
                </div>
                <div style={{ marginTop: 6, fontSize: 10, color: '#333', fontFamily: 'monospace' }}>
                    OID4VP request: {scenario.label}
                </div>
                <a
                    href={walletDeepLink}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ display: 'block', marginTop: 8, fontSize: 10, color: '#0891b2', wordBreak: 'break-all', textDecoration: 'none' }}
                >
                    Open in wallet →
                </a>
            </div>
        );
    }

    // --- VERIFIED ---
    if (panelState === 'verified') {
        const disclosed = statusData?.disclosedClaims ?? {};
        const hasRealData = Object.keys(disclosed).length > 0;

        return (
            <div>
                {/* Real disclosed claims from OID4VP validation */}
                {hasRealData ? (
                    <>
                        <div style={{ fontSize: 11, color: '#2e7d32', marginBottom: 10, fontWeight: 700 }}>
                            ✅ Cryptographically verified claims:
                        </div>
                        {Object.entries(disclosed).map(([key, value]) => (
                            <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                <span style={{ color: '#2e7d32', fontWeight: 700 }}>✅</span>
                                <span style={{ color: '#81c784', fontFamily: 'monospace', fontSize: 13 }}>
                                    {key}: {String(value)}
                                </span>
                            </div>
                        ))}
                    </>
                ) : (
                    // Fallback to scenario fixtures if no real data yet
                    scenario.verifierReceives.map((claim) => (
                        <div key={claim.key} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                            <span style={{ color: '#2e7d32', fontWeight: 700 }}>✅</span>
                            <span style={{ color: '#81c784', fontFamily: 'monospace', fontSize: 13 }}>
                                {claim.key}: {claim.isProof ? <em>proof only</em> : claim.value}
                            </span>
                        </div>
                    ))
                )}

                {/* Withheld fields */}
                {scenario.blocked.map((field) => (
                    <div key={field} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                        <span style={{ color: '#b71c1c', fontWeight: 700 }}>❌</span>
                        <span style={{ color: '#555', fontFamily: 'monospace', fontSize: 13 }}>
                            {field}: <span style={{ color: '#333' }}>[NOT RECEIVED]</span>
                        </span>
                    </div>
                ))}

                {/* Crypto-shred confirmation + consent receipt */}
                <div style={{
                    marginTop: 16, padding: '8px 12px',
                    background: '#0a1a0a', borderRadius: 8,
                    fontSize: 11, color: '#2e7d32', fontFamily: 'monospace',
                }}>
                    🔐 Session keys shredded — W-05 cleanup complete
                </div>
                {statusData?.consentReceipt && (
                    <div style={{
                        marginTop: 6, padding: '6px 10px',
                        background: '#0a0a14', borderRadius: 6,
                        fontSize: 10, color: '#444', fontFamily: 'monospace',
                    }}>
                        Receipt: {statusData.consentReceipt.id}
                    </div>
                )}
            </div>
        );
    }

    // --- FAILED ---
    if (panelState === 'failed') {
        return (
            <div style={{
                background: '#1a0505', padding: 16, borderRadius: 10,
                borderLeft: '3px solid #b71c1c', color: '#ef9a9a', fontSize: 14,
            }}>
                ⛔ Verification failed or credential denied
                {scenario.id === 'revoked' && (
                    <div style={{ marginTop: 8, fontSize: 11, color: '#b71c1c', fontFamily: 'monospace' }}>
                        Reason: Credential revoked (status_list check)
                    </div>
                )}
            </div>
        );
    }

    // --- OFFLINE ---
    return (
        <div style={{ textAlign: 'center', padding: 24, color: '#555' }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>⚡</div>
            <div style={{ fontSize: 13, marginBottom: 4 }}>Backend offline</div>
            <code style={{ fontSize: 11, color: '#444' }}>pnpm dev:verifier</code>
        </div>
    );
}
