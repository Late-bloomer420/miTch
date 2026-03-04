import type { ScenarioDefinition } from '../data/scenarios';

interface WalletPanelProps {
    scenario: ScenarioDefinition;
}

export function WalletPanel({ scenario }: WalletPanelProps) {
    return (
        <div>
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
                            <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{field.value}</span>
                        </div>
                    ))}
                </div>
            ))}
        </div>
    );
}
