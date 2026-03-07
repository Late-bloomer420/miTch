import { useState } from 'react';
import type { ScenarioDefinition } from '../data/scenarios';

interface WalletPanelProps {
    scenario: ScenarioDefinition;
    backendUrl: string;
    onPresented: () => void;
}

type FlowState = 'idle' | 'consent' | 'presenting' | 'done' | 'denied' | 'error';

export function WalletPanel({ scenario, backendUrl, onPresented }: WalletPanelProps) {
    const [flowState, setFlowState] = useState<FlowState>('idle');
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    const handlePresent = async () => {
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
            const data = await res.json() as { ok: boolean; errors?: string[]; error?: string };
            if (data.ok) {
                setFlowState('done');
                onPresented();
            } else {
                setFlowState('denied');
                setErrorMsg((data.errors ?? [data.error ?? 'Unknown error']).join(', '));
                onPresented();
            }
        } catch (e: unknown) {
            setFlowState('error');
            setErrorMsg(e instanceof Error ? e.message : String(e));
        }
    };

    const handleReset = () => {
        setFlowState('idle');
        setErrorMsg(null);
    };

    return (
        <div>
            {/* Credential display */}
            {scenario.walletCredentials.map((cred, idx) => (
                <div
                    key={idx}
                    style={{
                        background: '#111',
                        borderRadius: 10,
                        padding: 16,
                        marginBottom: 16,
                        borderLeft: '3px solid #1a237e',
                    }}
                >
                    <div style={{ fontWeight: 700, fontSize: 14, color: '#fff', marginBottom: 2 }}>
                        {cred.type}
                    </div>
                    <div style={{ fontSize: 11, color: '#555', fontFamily: 'monospace', marginBottom: 12 }}>
                        {cred.issuer}
                    </div>

                    {cred.fields.map((field) => (
                        <div
                            key={field.key}
                            style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '4px 0',
                                borderBottom: '1px solid #1a1a1a',
                                opacity: field.blocked ? 0.35 : 1,
                                textDecoration: field.blocked ? 'line-through' : 'none',
                                color: field.blocked ? '#555' : '#aaa',
                            }}
                        >
                            <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{field.key}</span>
                            <span style={{ fontSize: 12, fontFamily: 'monospace' }}>
                                {field.blocked ? '[withheld]' : field.value}
                            </span>
                        </div>
                    ))}
                </div>
            ))}

            {/* W-02: Consent Flow */}
            {flowState === 'idle' && (
                <button
                    onClick={handlePresent}
                    style={{
                        width: '100%', padding: '12px 0', marginTop: 8,
                        background: '#1a237e', color: '#fff', border: 'none',
                        borderRadius: 8, cursor: 'pointer', fontSize: 14, fontWeight: 700,
                    }}
                >
                    Present Credentials →
                </button>
            )}

            {flowState === 'consent' && (
                <div style={{
                    background: '#0d1117', border: '1px solid #1a237e',
                    borderRadius: 10, padding: 16, marginTop: 8,
                }}>
                    <div style={{ fontWeight: 700, fontSize: 13, color: '#7986cb', marginBottom: 8 }}>
                        🔐 Consent Required
                    </div>
                    <div style={{ fontSize: 12, color: '#aaa', marginBottom: 10 }}>
                        <strong style={{ color: '#fff' }}>{scenario.label}</strong> is requesting:
                    </div>
                    {scenario.verifierReceives.map((claim) => (
                        <div key={claim.key} style={{ fontSize: 12, color: '#81c784', fontFamily: 'monospace', marginBottom: 4 }}>
                            ✓ {claim.key}
                        </div>
                    ))}
                    {scenario.blocked.length > 0 && (
                        <>
                            <div style={{ fontSize: 11, color: '#555', marginTop: 8, marginBottom: 4 }}>
                                Not shared (withheld by miTch):
                            </div>
                            {scenario.blocked.map((field) => (
                                <div key={field} style={{ fontSize: 11, color: '#444', fontFamily: 'monospace', marginBottom: 2 }}>
                                    ✗ {field}
                                </div>
                            ))}
                        </>
                    )}
                    <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                        <button
                            onClick={handleConsent}
                            style={{
                                flex: 1, padding: '10px 0',
                                background: '#2e7d32', color: '#fff', border: 'none',
                                borderRadius: 8, cursor: 'pointer', fontSize: 13, fontWeight: 700,
                            }}
                        >
                            Share & Present
                        </button>
                        <button
                            onClick={handleReset}
                            style={{
                                flex: 1, padding: '10px 0',
                                background: '#1a1a1a', color: '#888', border: '1px solid #333',
                                borderRadius: 8, cursor: 'pointer', fontSize: 13,
                            }}
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}

            {flowState === 'presenting' && (
                <div style={{ textAlign: 'center', padding: '16px 0', color: '#7986cb', fontSize: 13 }}>
                    <div style={{ marginBottom: 6 }}>⏳ Signing & presenting…</div>
                    <div style={{ fontSize: 10, color: '#444' }}>
                        SD-JWT VC + Key Binding JWT + OID4VP
                    </div>
                </div>
            )}

            {flowState === 'done' && (
                <div style={{
                    background: '#0a1a0a', border: '1px solid #2e7d32',
                    borderRadius: 10, padding: 12, marginTop: 8,
                }}>
                    <div style={{ color: '#81c784', fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                        ✅ Presentation sent
                    </div>
                    <div style={{ fontSize: 10, color: '#2e7d32', fontFamily: 'monospace' }}>
                        SD-JWT VC + KB-JWT → verified by verifier
                    </div>
                    <button onClick={handleReset} style={{
                        marginTop: 10, padding: '6px 14px',
                        background: 'transparent', color: '#555', border: '1px solid #222',
                        borderRadius: 6, cursor: 'pointer', fontSize: 11,
                    }}>
                        Reset
                    </button>
                </div>
            )}

            {(flowState === 'denied' || flowState === 'error') && (
                <div style={{
                    background: '#1a0505', border: '1px solid #b71c1c',
                    borderRadius: 10, padding: 12, marginTop: 8,
                }}>
                    <div style={{ color: '#ef9a9a', fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                        {flowState === 'denied' ? '⛔ Presentation denied' : '⚠️ Error'}
                    </div>
                    {errorMsg && (
                        <div style={{ fontSize: 11, color: '#b71c1c', fontFamily: 'monospace' }}>
                            {errorMsg}
                        </div>
                    )}
                    <button onClick={handleReset} style={{
                        marginTop: 10, padding: '6px 14px',
                        background: 'transparent', color: '#555', border: '1px solid #222',
                        borderRadius: 6, cursor: 'pointer', fontSize: 11,
                    }}>
                        Reset
                    </button>
                </div>
            )}
        </div>
    );
}
