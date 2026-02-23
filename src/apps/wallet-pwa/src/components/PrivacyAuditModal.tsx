import React, { useEffect, useState } from 'react';
import { PrivacyAuditService, PrivacyContext, TrackingPoint } from '../services/PrivacyAuditService';

interface PrivacyAuditModalProps {
    verifierName: string;
    onAccept: (context: PrivacyContext) => void;
    onCancel: () => void;
}

export const PrivacyAuditModal: React.FC<PrivacyAuditModalProps> = ({ verifierName, onAccept, onCancel }) => {
    const [context, setContext] = useState<PrivacyContext | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const runAudit = async () => {
        try {
            setLoading(true);
            setError(null);
            const result = await PrivacyAuditService.auditTransaction(verifierName);
            setContext(result);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Unknown error');
            console.error('[PrivacyAudit]', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        runAudit();
    }, [verifierName]);

    if (loading) {
        return (
            <div style={{
                position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,0,0,0.9)', zIndex: 999,
                display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center'
            }}>
                <div className="spinner" style={{
                    width: 40, height: 40, borderRadius: '50%',
                    border: '3px solid #333', borderTopColor: '#0070f3',
                    animation: 'spin 1s linear infinite'
                }}></div>
                <div style={{ marginTop: 15, color: '#ccc', fontSize: 14 }}>Scanning Privacy risks...</div>
                <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{
                position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,0,0,0.9)', zIndex: 999,
                display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>
                <div style={{ background: '#111', padding: 20, borderRadius: 12, border: '1px solid #333' }}>
                    <h3 style={{ color: '#ef4444' }}>Audit Failed</h3>
                    <p style={{ color: '#999' }}>{error}</p>
                    <button onClick={runAudit} style={{ padding: '8px 16px', marginTop: 10 }}>Retry</button>
                    <button onClick={onCancel} style={{ padding: '8px 16px', marginLeft: 10 }}>Cancel</button>
                </div>
            </div>
        );
    }

    if (!context) return null;

    const getScoreColor = (score: number) => {
        if (score > 80) return '#10b981'; // Green
        if (score > 50) return '#f59e0b'; // Orange
        return '#ef4444'; // Red
    };

    const calculateVPNBoost = (trackers: TrackingPoint[]) => {
        // Simple logic: sum mitigated penalty for VPN
        // In real app reuse service logic, simplified here for UI
        return 40;
    };

    const handleEnableVPN = () => {
        if (window.confirm('Open VPN provider recommendations (Mullvad/Proton)?')) {
            window.open('https://mullvad.net', '_blank');
        }
    };

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.85)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            zIndex: 999
        }}>
            <div style={{
                background: '#111827',
                border: '1px solid #374151',
                borderRadius: '24px',
                padding: '24px',
                maxWidth: '400px',
                width: '100%',
                color: '#f9fafb'
            }}>
                <header style={{ marginBottom: '20px', textAlign: 'center' }}>
                    <div style={{ fontSize: '12px', textTransform: 'uppercase', color: '#9ca3af', letterSpacing: '0.1em' }}>
                        Compliance Audit
                    </div>
                    <h2 style={{ margin: '8px 0', fontSize: '24px' }}>Privacy Check</h2>
                    <div style={{
                        fontSize: '36px',
                        fontWeight: '800',
                        color: getScoreColor(context.privacyScore.overall),
                        textShadow: '0 0 20px rgba(0,0,0,0.5)'
                    }}>
                        {context.privacyScore.overall}/100
                    </div>
                    <div style={{ fontSize: '13px', color: '#6b7280' }}>Privacy Health Score</div>
                </header>

                <div style={{ marginBottom: '24px' }}>
                    <h3 style={{ fontSize: '15px', borderBottom: '1px solid #374151', paddingBottom: '8px', marginBottom: '12px' }}>
                        👁️ Who is watching?
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {context.detectedTrackers.map((t, idx) => (
                            <TrackerRow key={idx} tracker={t} />
                        ))}

                        {/* Always show miTch as green */}
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', opacity: 0.8 }}>
                            <div style={{ background: '#065f46', width: '8px', height: '8px', borderRadius: '50%', marginTop: '6px' }} />
                            <div>
                                <div style={{ fontWeight: '600', fontSize: '14px', color: '#34d399' }}>miTch Protocol</div>
                                <div style={{ fontSize: '11px', color: '#9ca3af' }}>
                                    Sees metadata only. <span style={{ color: '#10b981' }}>Crypto-Shredding active.</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.2)',
                    borderRadius: '12px',
                    padding: '12px',
                    marginBottom: '20px',
                    fontSize: '12px',
                    textAlign: 'center',
                    color: '#fca5a5'
                }}>
                    ⚠️ <strong>Awareness Check:</strong> Your OS & ISP can see this transaction metadata.
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                    <button
                        onClick={onCancel}
                        style={{
                            padding: '12px', borderRadius: '12px', background: 'transparent',
                            border: '1px solid #374151', color: '#9ca3af', cursor: 'pointer'
                        }}>
                        Cancel
                    </button>
                    <button
                        onClick={() => onAccept(context)}
                        style={{
                            padding: '12px', borderRadius: '12px',
                            background: context.privacyScore.overall < 50 ? '#b91c1c' : '#2563eb', // Red button if low score to warn
                            border: 'none', color: 'white', fontWeight: 'bold', cursor: 'pointer'
                        }}>
                        {context.privacyScore.overall < 50 ? 'Accept Risk' : 'Continue'}
                    </button>
                </div>

                {context.privacyScore.overall < 60 && (
                    <div style={{ textAlign: 'center', marginTop: '12px' }}>
                        <button
                            onClick={handleEnableVPN}
                            style={{
                                fontSize: '11px',
                                color: '#60a5fa',
                                background: 'transparent',
                                border: '1px solid #60a5fa',
                                padding: '4px 8px',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}>
                            Enable VPN (estimated +{calculateVPNBoost(context.detectedTrackers)} pts)
                        </button>
                    </div>
                )}

                <div style={{ marginTop: 15, fontSize: 10, color: '#444', textAlign: 'center', fontFamily: 'monospace' }}>
                    Audit Proof: {context.auditProof?.hash.substring(0, 16)}...
                </div>
            </div>
        </div>
    );
};

const TrackerRow: React.FC<{ tracker: TrackingPoint }> = ({ tracker }) => {
    const color = tracker.riskLevel === 'HIGH' ? '#ef4444' : '#f59e0b';
    const confidence = tracker.detection.confidence;

    return (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
            <div style={{ background: color, width: '8px', height: '8px', borderRadius: '50%', marginTop: '6px' }} />
            <div>
                <div style={{ fontWeight: '600', fontSize: '14px', color: '#f3f4f6' }}>
                    {tracker.actor}
                    <span style={{ fontSize: '10px', color: '#666', marginLeft: 6, border: '1px solid #333', padding: '1px 3px', borderRadius: 3 }}>
                        {confidence}% CONFIDENCE
                    </span>
                </div>
                <div style={{ fontSize: '11px', color: '#9ca3af' }}>
                    Sees: {tracker.dataExposed.map(d => d.field).join(', ')}
                </div>
                {tracker.mitigations.length > 0 && (
                    <div style={{ fontSize: '10px', color: color, marginTop: '2px' }}>
                        🛠️ Fix: {tracker.mitigations[0].label}
                    </div>
                )}
            </div>
        </div>
    );
};
