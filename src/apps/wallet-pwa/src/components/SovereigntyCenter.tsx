import React, { useMemo, useState } from 'react';
import { InsightAggregator } from '@askmi/data-flow';
import type { AuditLogEntry } from '@askmi/shared-types';

interface SovereigntyCenterProps {
    auditEntries: AuditLogEntry[];
    onClose: () => void;
}

/**
 * miTch Sovereignty Center (v1.1 Alpha)
 * 
 * Refactored to "Facts First" philosophy. 
 * Estimates are hidden behind interactive expansions.
 */
export const SovereigntyCenter: React.FC<SovereigntyCenterProps> = ({ auditEntries, onClose }) => {
    const metrics = useMemo(() => InsightAggregator.aggregate(auditEntries), [auditEntries]);
    const [showAdvanced, setShowSovereigntyAdvanced] = useState(false);
    const [expandedConsumers, setExpandedConsumers] = useState(false);

    // Simple Heatmap Generation (Last 14 days)
    const heatmapDays = useMemo(() => {
        const days = [];
        for (let i = 13; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            const key = d.toISOString().split('T')[0];
            days.push({
                date: key,
                count: metrics.exposureByDay[key] || 0
            });
        }
        return days;
    }, [metrics]);

    return (
        <div className="sovereignty-center" style={{
            background: '#0a0a0b',
            color: '#fff',
            padding: '32px',
            borderRadius: '16px',
            maxWidth: '600px',
            width: '95vw',
            maxHeight: '90vh',
            overflowY: 'auto',
            boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
            border: '1px solid #1f2937',
            position: 'relative',
            fontFamily: 'Inter, system-ui, sans-serif'
        }}>
            <button onClick={onClose} style={{
                position: 'absolute', top: 16, right: 16, background: 'none', border: 'none', color: '#94a3b8', fontSize: '20px', cursor: 'pointer', zIndex: 10
            }}>✕</button>

            <header style={{ marginBottom: 32 }}>
                <h2 style={{ fontSize: '24px', fontWeight: 800, margin: 0, letterSpacing: '-0.5px' }}>
                    Sovereignty <span style={{ color: '#0891b2' }}>Center</span>
                </h2>
                <p style={{ color: '#94a3b8', fontSize: '13px', marginTop: 4 }}>
                    <span style={{ color: '#059669', fontWeight: 600 }}>✓ Verified Evidence</span> — Device-only Analysis
                </p>
            </header>

            {/* --- SECTION 1: FACTUAL DATA (PRIMARY) --- */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: 24 }}>
                <div style={{ padding: '20px', background: '#111827', borderRadius: '12px', border: '1px solid #1f2937' }}>
                    <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 600, marginBottom: 8 }}>
                        Data Transmissions Minimized
                    </div>
                    <div style={{ fontSize: '32px', fontWeight: 800, color: '#0891b2' }}>
                        {metrics.minimizedTransactions}
                    </div>
                    <div style={{ fontSize: '10px', color: '#4b5563', marginTop: 8 }}>
                        Actual requests processed via Zero-Knowledge Proofs.
                    </div>
                </div>
                <div style={{ padding: '20px', background: '#111827', borderRadius: '12px', border: '1px solid #1f2937' }}>
                    <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 600, marginBottom: 8 }}>
                        Aggressive Requests Blocked
                    </div>
                    <div style={{ fontSize: '32px', fontWeight: 800, color: '#e11d48' }}>
                        {metrics.blockedTransactions}
                    </div>
                    <div style={{ fontSize: '10px', color: '#4b5563', marginTop: 8 }}>
                        Direct attempts to access unauthorized PII.
                    </div>
                </div>
            </div>

            {/* --- SECTION 2: TOP CONSUMERS (FACTUAL) --- */}
            <div style={{ background: '#111827', borderRadius: '12px', padding: '20px', marginBottom: 24, border: '1px solid #1f2937' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                    <h3 style={{ fontSize: '13px', fontWeight: 700, margin: 0 }}>Active Data Consumers</h3>
                    <button 
                        onClick={() => setExpandedConsumers(!expandedConsumers)}
                        style={{ background: 'none', border: 'none', color: '#0891b2', fontSize: '12px', cursor: 'pointer', fontWeight: 600 }}
                    >
                        {expandedConsumers ? 'Show Less' : 'View Full Audit Statistics →'}
                    </button>
                </div>
                
                {metrics.topDataConsumers.length > 0 ? (
                    metrics.topDataConsumers.slice(0, expandedConsumers ? 10 : 3).map((c, i) => (
                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid #1f2937' }}>
                            <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#e5e7eb' }}>
                                {c.name.length > 40 ? c.name.substring(0, 40) + '...' : c.name}
                            </span>
                            <span style={{ fontSize: '12px', fontWeight: 700, color: '#0891b2' }}>{c.count} pts</span>
                        </div>
                    ))
                ) : (
                    <div style={{ color: '#4b5563', fontSize: '12px', fontStyle: 'italic' }}>No consumer activity recorded.</div>
                )}

                {expandedConsumers && (
                    <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px dashed #374151' }}>
                         <div style={{ fontSize: '11px', color: '#94a3b8', lineHeight: 1.6 }}>
                            <strong>Statistical Integrity:</strong> These numbers are derived from your cryptographically signed WORM Audit Log. 
                            Each entry represents a unique verification session anchored to your hardware key.
                         </div>
                    </div>
                )}
            </div>

            {/* --- SECTION 3: ESTIMATED DATA (HIDDEN/ADVANCED) --- */}
            <div style={{ marginTop: 32 }}>
                <button 
                    onClick={() => setShowSovereigntyAdvanced(!showAdvanced)}
                    style={{
                        width: '100%',
                        padding: '12px',
                        background: showAdvanced ? '#1f2937' : '#111827',
                        border: '1px solid #374151',
                        borderRadius: '8px',
                        color: showAdvanced ? '#fff' : '#94a3b8',
                        fontSize: '13px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        gap: '8px',
                        transition: 'all 0.2s ease'
                    }}
                >
                    {showAdvanced ? '🔽 Hide Economic Impact & Projections' : '🚀 Expand Data Value & Economic Insights'}
                </button>

                {showAdvanced && (
                    <div style={{ marginTop: 24, animation: 'fadeIn 0.3s ease' }}>
                        <div style={{
                            padding: '24px',
                            background: 'linear-gradient(135deg, #0f172a 0%, #0a0a0b 100%)',
                            borderRadius: '12px',
                            border: '1px solid #0891b2',
                            textAlign: 'center',
                            marginBottom: 24
                        }}>
                            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#0891b2', fontWeight: 700, marginBottom: 8 }}>
                                Estimated Data Value Retained
                            </div>
                            <div style={{ fontSize: '42px', fontWeight: 800, fontFamily: 'monospace' }}>
                                €{metrics.estimatedValueRetained.toFixed(2)}
                            </div>
                            <div style={{ display: 'inline-block', background: 'rgba(8, 145, 178, 0.1)', padding: '4px 12px', borderRadius: '100px', marginTop: 12 }}>
                                <span style={{ color: '#0891b2', fontSize: '10px', fontWeight: 700 }}>PROJECTION</span>
                            </div>
                            <p style={{ color: '#64748b', fontSize: '11px', marginTop: 16, textAlign: 'left', lineHeight: 1.5 }}>
                                <strong>About this estimate:</strong> This calculation uses current market prices for PII in the ad-tech and data-brokerage industry. 
                                It visualizes the economic benefit of your privacy policy by projecting what an entity would have to pay to acquire this data elsewhere.
                            </p>
                        </div>

                        {/* --- Exposure Heatmap --- */}
                        <div style={{ background: '#111827', padding: '20px', borderRadius: '12px', border: '1px solid #1f2937' }}>
                            <h3 style={{ fontSize: '13px', color: '#94a3b8', marginBottom: 16 }}>Privacy Intensity Projection</h3>
                            <div style={{ display: 'flex', gap: '6px', alignItems: 'flex-end', height: '80px', marginBottom: 12 }}>
                                {heatmapDays.map(day => (
                                    <div key={day.date} title={`${day.date}: ${day.count} requests`} style={{
                                        flex: 1,
                                        background: day.count > 0 ? `rgba(8, 145, 178, ${Math.min(0.2 + day.count * 0.2, 1)})` : '#1f2937',
                                        height: `${Math.min(20 + day.count * 20, 100)}%`,
                                        borderRadius: '3px',
                                        transition: 'all 0.3s ease'
                                    }} />
                                ))}
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#4b5563' }}>
                                <span>14 Days Ago</span>
                                <span>Today</span>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            <footer style={{ marginTop: 40, paddingTop: 20, borderTop: '1px solid #1f2937', textAlign: 'center' }}>
                <div style={{ fontSize: '11px', color: '#4b5563' }}>
                    miTch Sovereignty Index v1.0 • <span style={{ color: '#0891b2' }}>Protecting human value.</span>
                </div>
            </footer>

            <style dangerouslySetInnerHTML={{ __html: `
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            `}} />
        </div>
    );
};
