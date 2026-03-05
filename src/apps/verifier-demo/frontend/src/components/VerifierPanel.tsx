import { useState, useEffect, useRef } from 'react';
import QRCode from 'react-qr-code';
import type { ScenarioDefinition } from '../data/scenarios';

interface VerifierPanelProps {
    scenario: ScenarioDefinition;
    backendUrl: string;
    runNonce: number;
}

export function VerifierPanel({ scenario, backendUrl, runNonce }: VerifierPanelProps) {
    const [panelState, setPanelState] = useState<'waiting' | 'verified' | 'failed' | 'offline'>('waiting');
    const lastSeenProofHash = useRef<string | null>(null);

    // Reset when runNonce changes (scenario switch)
    useEffect(() => {
        setPanelState('waiting');
        lastSeenProofHash.current = null;
    }, [runNonce]);

    // Polling with throttled error handling
    useEffect(() => {
        let errorCount = 0;
        const MAX_CONSECUTIVE_ERRORS = 3;

        const poll = async () => {
            try {
                const res = await fetch(`${backendUrl}/status`);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();
                errorCount = 0;

                if (data.status === 'VERIFIED' && data.lastProof) {
                    const proofHash = JSON.stringify(data.lastProof);
                    if (proofHash !== lastSeenProofHash.current) {
                        lastSeenProofHash.current = proofHash;
                        setPanelState('verified');
                    }
                } else if (data.status === 'FAILED') {
                    setPanelState('failed');
                }
            } catch {
                errorCount++;
                if (errorCount >= MAX_CONSECUTIVE_ERRORS) {
                    setPanelState('offline');
                }
            }
        };

        const intervalId = setInterval(poll, 1500);
        poll();
        return () => clearInterval(intervalId);
    }, [backendUrl, runNonce]);

    // --- WAITING ---
    if (panelState === 'waiting') {
        return (
            <div style={{ textAlign: 'center', padding: 24 }}>
                <QRCode
                    value={`mitch://present?verifier=${encodeURIComponent(backendUrl)}`}
                    size={180}
                    bgColor="#ffffff"
                    fgColor="#0a0a0a"
                />
                <div style={{ marginTop: 12, color: '#555', fontSize: 13 }}>
                    ● Waiting for wallet...
                </div>
            </div>
        );
    }

    // --- VERIFIED ---
    if (panelState === 'verified') {
        return (
            <div>
                {scenario.verifierReceives.map((claim) => (
                    <div key={claim.key} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                        <span style={{ color: '#2e7d32', fontWeight: 700 }}>✅</span>
                        <span style={{ color: '#81c784', fontFamily: 'monospace', fontSize: 13 }}>
                            {claim.key}: {claim.isProof ? <em>proof only</em> : claim.value}
                        </span>
                    </div>
                ))}

                {scenario.blocked.map((field) => (
                    <div key={field} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                        <span style={{ color: '#b71c1c', fontWeight: 700 }}>❌</span>
                        <span style={{ color: '#555', fontFamily: 'monospace', fontSize: 13 }}>
                            {field}: <span style={{ color: '#333' }}>[NOT RECEIVED]</span>
                        </span>
                    </div>
                ))}

                <div style={{
                    marginTop: 16, padding: '8px 12px',
                    background: '#0a1a0a', borderRadius: 8,
                    fontSize: 11, color: '#2e7d32',
                    fontFamily: 'monospace',
                }}>
                    🔐 Crypto-Shredding simulated — session key not retained (demo)
                </div>
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
                ⛔ Verification failed or denied by user
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
