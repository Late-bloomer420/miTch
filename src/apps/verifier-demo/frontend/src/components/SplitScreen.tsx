import { useState } from 'react';
import { SCENARIOS, SCENARIO_ORDER } from '../data/scenarios';
import type { ScenarioId } from '../data/scenarios';
import { WalletPanel } from './WalletPanel';
import { VerifierPanel } from './VerifierPanel';

interface SplitScreenProps {
    backendUrl: string;
}

export function SplitScreen({ backendUrl }: SplitScreenProps) {
    const [selectedId, setSelectedId] = useState<ScenarioId>('liquor-store');
    const [runNonce, setRunNonce] = useState(0);
    const scenario = SCENARIOS[selectedId];

    const handleScenarioChange = (id: ScenarioId) => {
        setSelectedId(id);
        setRunNonce((prev) => prev + 1);
    };

    return (
        <div style={{
            display: 'flex', flexDirection: 'column', height: '100vh',
            background: '#0a0a0a', color: '#fff', fontFamily: 'system-ui, sans-serif',
        }}>

            {/* Header */}
            <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '14px 24px', borderBottom: '1px solid #1a1a1a', flexShrink: 0,
            }}>
                <div style={{ fontWeight: 700, fontSize: 16 }}>
                    🔐 miTch — Proof, not Person
                </div>
                <select
                    value={selectedId}
                    onChange={(e) => handleScenarioChange(e.target.value as ScenarioId)}
                    style={{
                        background: '#111', color: '#fff', border: '1px solid #333',
                        borderRadius: 8, padding: '6px 12px', cursor: 'pointer', fontSize: 14,
                    }}
                >
                    {SCENARIO_ORDER.map((id) => (
                        <option key={id} value={id}>
                            {SCENARIOS[id].emoji} {SCENARIOS[id].label}
                        </option>
                    ))}
                </select>
            </div>

            {/* Split Area */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: 1, overflow: 'hidden' }}>
                {/* Left: Wallet */}
                <div style={{
                    borderRight: '1px solid #1a1a1a', overflow: 'auto',
                    padding: 24, background: '#0a0a14',
                }}>
                    <div style={{
                        fontSize: 11, color: '#1a237e', fontWeight: 700,
                        letterSpacing: 2, marginBottom: 16,
                    }}>
                        📱 WALLET — YOUR DATA
                    </div>
                    <WalletPanel scenario={scenario} />
                </div>

                {/* Right: Verifier */}
                <div style={{ overflow: 'auto', padding: 24, background: '#0a0a0a' }}>
                    <div style={{
                        fontSize: 11, color: '#1b5e20', fontWeight: 700,
                        letterSpacing: 2, marginBottom: 16,
                    }}>
                        🏪 VERIFIER — WHAT THEY RECEIVE
                    </div>
                    <VerifierPanel scenario={scenario} backendUrl={backendUrl} runNonce={runNonce} />
                </div>
            </div>

            {/* Bottom Tab Bar */}
            <div style={{
                display: 'flex', borderTop: '1px solid #1a1a1a',
                flexShrink: 0, background: '#050505',
            }}>
                {SCENARIO_ORDER.map((id) => {
                    const s = SCENARIOS[id];
                    const isActive = id === selectedId;
                    return (
                        <button
                            key={id}
                            onClick={() => handleScenarioChange(id)}
                            style={{
                                flex: 1, padding: '12px 8px',
                                background: isActive ? '#111' : 'transparent',
                                border: 'none',
                                borderTop: isActive ? '2px solid #00bfff' : '2px solid transparent',
                                color: isActive ? '#fff' : '#555',
                                cursor: 'pointer',
                                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
                            }}
                        >
                            <span style={{ fontSize: 18 }}>{s.emoji}</span>
                            <span style={{ fontSize: 11 }}>{s.label}</span>
                            <span style={{
                                fontSize: 9, padding: '1px 6px', borderRadius: 3,
                                background: s.verdict === 'ALLOW' ? '#1b5e20'
                                    : s.verdict === 'PROMPT+BIOMETRIC' ? '#4a148c' : '#e65100',
                                color: '#fff',
                            }}>
                                {s.verdict}
                            </span>
                        </button>
                    );
                })}
            </div>
        </div>
    );
}
