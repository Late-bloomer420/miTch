import React, { useState, useEffect } from "react";
import { PolicyManifest, TrustedIssuer } from "@mitch/shared-types";

interface PolicyEditorProps {
    policy: PolicyManifest;
    onSave: (policy: PolicyManifest) => void;
}

export const PolicyEditor: React.FC<PolicyEditorProps> = ({ policy: initialPolicy, onSave }) => {
    const [policy, setPolicy] = useState<PolicyManifest>(initialPolicy);
    const [newIssuer, setNewIssuer] = useState({ did: '', name: '', credentialTypes: 'AgeCredential' });
    const [isSaved, setIsSaved] = useState(false);

    useEffect(() => {
        setPolicy(initialPolicy);
    }, [initialPolicy]);

    const handleToggleBlockUnknown = () => {
        setPolicy({
            ...policy,
            globalSettings: {
                ...policy.globalSettings,
                blockUnknownVerifiers: !policy.globalSettings?.blockUnknownVerifiers
            }
        });
        setIsSaved(false);
    };

    const removeIssuer = (did: string) => {
        setPolicy({
            ...policy,
            trustedIssuers: policy.trustedIssuers.filter(i => i.did !== did)
        });
        setIsSaved(false);
    };

    const addIssuer = () => {
        if (!newIssuer.did || !newIssuer.name) return;
        const issuer: TrustedIssuer = {
            did: newIssuer.did,
            name: newIssuer.name,
            credentialTypes: newIssuer.credentialTypes.split(',').map(t => t.trim())
        };
        setPolicy({
            ...policy,
            trustedIssuers: [...policy.trustedIssuers, issuer]
        });
        setNewIssuer({ did: '', name: '', credentialTypes: 'AgeCredential' });
        setIsSaved(false);
    };

    const handleSave = () => {
        onSave(policy);
        setIsSaved(true);
        setTimeout(() => setIsSaved(false), 3000);
    };

    const addBlockedVerifier = (pattern: string) => {
        if (!pattern) return;
        // Create a high-priority "DENY-ALL" rule for this pattern
        const vetoRule = {
            id: `veto-${Date.now()}`,
            verifierPattern: pattern,
            allowedClaims: [],
            provenClaims: [],
            priority: 999, // Overrides everything
            requiresUserConsent: false
        };
        setPolicy({
            ...policy,
            rules: [vetoRule, ...policy.rules]
        });
        setIsSaved(false);
    };

    const removeRule = (id: string) => {
        setPolicy({
            ...policy,
            rules: policy.rules.filter(r => r.id !== id)
        });
        setIsSaved(false);
    };

    return (
        <div className="policy-editor" style={{
            padding: '24px',
            background: '#111827',
            borderRadius: '24px',
            border: '1px solid #374151',
            color: '#f9fafb',
            marginTop: '30px'
        }}>
            <header style={{ marginBottom: '20px' }}>
                <h3 style={{ margin: 0, fontSize: '20px', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>⚖️</span> Governance Settings
                </h3>
                <p style={{ fontSize: '13px', color: '#9ca3af', margin: '8px 0 0 0' }}>
                    Manage which issuers you trust and how your data is protected.
                </p>
            </header>

            {/* Veto / Blacklist Section */}
            <div style={{ marginBottom: '25px' }}>
                <h4 style={{ fontSize: '12px', color: '#f87171', textTransform: 'uppercase', marginBottom: '12px', letterSpacing: '0.05em' }}>
                    🚫 Active Veto List (Hard Block)
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {policy.rules.filter(r => r.priority === 999).map(rule => (
                        <div key={rule.id} style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            background: 'rgba(248, 113, 113, 0.05)',
                            padding: '10px 16px',
                            borderRadius: '12px',
                            border: '1px solid rgba(248, 113, 113, 0.2)'
                        }}>
                            <div style={{ fontSize: '13px', fontWeight: '600', color: '#f87171' }}>{rule.verifierPattern}</div>
                            <button
                                onClick={() => removeRule(rule.id)}
                                style={{ background: 'transparent', border: 'none', color: '#6b7280', cursor: 'pointer' }}
                            >
                                ✕
                            </button>
                        </div>
                    ))}
                    <div style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
                        <input
                            id="veto-input"
                            placeholder="e.g. evil-tracker.com"
                            style={{ flex: 1, background: '#000', border: '1px solid #374151', color: 'white', padding: '8px', borderRadius: '8px', fontSize: '12px' }}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                    addBlockedVerifier(e.currentTarget.value);
                                    e.currentTarget.value = '';
                                }
                            }}
                        />
                        <button
                            onClick={() => {
                                const input = document.getElementById('veto-input') as HTMLInputElement;
                                addBlockedVerifier(input.value);
                                input.value = '';
                            }}
                            style={{ background: '#374151', color: 'white', border: 'none', padding: '0 12px', borderRadius: '8px', fontSize: '12px', fontWeight: 'bold' }}
                        >
                            Block
                        </button>
                    </div>
                </div>
            </div>

            {/* Global Settings */}
            <div style={{ marginBottom: '25px', padding: '16px', background: '#1f2937', borderRadius: '16px', border: '1px solid #374151' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                        <div style={{ fontWeight: '600', fontSize: '14px' }}>Block Unknown Verifiers</div>
                        <div style={{ fontSize: '11px', color: '#6b7280' }}>Only respond to verifiers matched by your rules.</div>
                    </div>
                    <button
                        onClick={handleToggleBlockUnknown}
                        style={{
                            width: '44px',
                            height: '24px',
                            borderRadius: '12px',
                            background: policy.globalSettings?.blockUnknownVerifiers ? '#10b981' : '#374151',
                            border: 'none',
                            position: 'relative',
                            cursor: 'pointer',
                            transition: 'background 0.2s'
                        }}
                    >
                        <div style={{
                            width: '18px',
                            height: '18px',
                            borderRadius: '50%',
                            background: 'white',
                            position: 'absolute',
                            top: '3px',
                            left: policy.globalSettings?.blockUnknownVerifiers ? '23px' : '3px',
                            transition: 'left 0.2s'
                        }} />
                    </button>
                </div>
            </div>

            {/* Trusted Issuers */}
            <div style={{ marginBottom: '25px' }}>
                <h4 style={{ fontSize: '12px', color: '#9ca3af', textTransform: 'uppercase', marginBottom: '12px', letterSpacing: '0.05em' }}>
                    Trusted Issuers
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {policy.trustedIssuers.map(issuer => (
                        <div key={issuer.did} style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            background: '#1f2937',
                            padding: '12px 16px',
                            borderRadius: '12px',
                            border: '1px solid #374151'
                        }}>
                            <div>
                                <div style={{ fontWeight: '600', fontSize: '13px' }}>{issuer.name}</div>
                                <div style={{ fontSize: '11px', color: '#6b7280', fontFamily: 'monospace' }}>{issuer.did}</div>
                                <div style={{ marginTop: '4px' }}>
                                    {issuer.credentialTypes.map(t => (
                                        <span key={t} style={{
                                            fontSize: '10px',
                                            padding: '2px 8px',
                                            background: 'rgba(99, 102, 241, 0.1)',
                                            color: '#818cf8',
                                            borderRadius: '4px',
                                            marginRight: '4px',
                                            border: '1px solid rgba(99, 102, 241, 0.2)'
                                        }}>{t}</span>
                                    ))}
                                </div>
                            </div>
                            <button
                                onClick={() => removeIssuer(issuer.did)}
                                style={{ background: 'transparent', border: 'none', color: '#f87171', cursor: 'pointer', padding: '8px' }}
                            >
                                🗑️
                            </button>
                        </div>
                    ))}
                </div>

                {/* Add Issuer Form */}
                <div style={{ marginTop: '12px', padding: '16px', background: 'rgba(0,0,0,0.2)', borderRadius: '16px', border: '1px dashed #374151' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '8px' }}>
                        <input
                            placeholder="Issuer Name (e.g. MyBank)"
                            value={newIssuer.name}
                            onChange={e => setNewIssuer({ ...newIssuer, name: e.target.value })}
                            style={{ background: '#000', border: '1px solid #374151', color: 'white', padding: '8px', borderRadius: '8px', fontSize: '12px' }}
                        />
                        <input
                            placeholder="DID (did:example:...)"
                            value={newIssuer.did}
                            onChange={e => setNewIssuer({ ...newIssuer, did: e.target.value })}
                            style={{ background: '#000', border: '1px solid #374151', color: 'white', padding: '8px', borderRadius: '8px', fontSize: '12px' }}
                        />
                    </div>
                    <button
                        onClick={addIssuer}
                        style={{
                            width: '100%',
                            padding: '8px',
                            background: '#374151',
                            color: 'white',
                            border: 'none',
                            borderRadius: '8px',
                            fontSize: '12px',
                            fontWeight: '600',
                            cursor: 'pointer'
                        }}
                    >
                        + Add Trusted Issuer
                    </button>
                </div>
            </div>

            <button
                onClick={handleSave}
                style={{
                    width: '100%',
                    padding: '14px',
                    borderRadius: '16px',
                    border: 'none',
                    background: isSaved ? '#10b981' : 'linear-gradient(to right, #4f46e5, #06b6d4)',
                    color: 'white',
                    fontWeight: '700',
                    cursor: 'pointer',
                    fontSize: '15px',
                    transition: 'all 0.3s'
                }}
            >
                {isSaved ? '✅ Policy Saved & Persistent' : 'Save Changes'}
            </button>
        </div>
    );
};
