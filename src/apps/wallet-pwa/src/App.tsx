import { useState, useEffect, useRef, useCallback } from 'react';
import './App.css';

import {
    type EvaluationContext
} from '@mitch/policy-engine';
import type { VerifierRequest, PolicyEvaluationResult, PolicyManifest } from '@mitch/shared-types';
import { WalletService } from './services/WalletService';
import { ComplianceDashboard } from './components/AuditReportPanel';
import { PolicyEditor } from './components/PolicyEditor';
import { WebAuthnService } from '@mitch/shared-crypto';
import { PrivacyAuditModal } from './components/PrivacyAuditModal';
import { PrivacyContext, PrivacyConsent } from './services/PrivacyAuditService';
import { ConsentModal } from './components/ConsentModal';
import { CONFIG } from './config';
import { GuidedDemoMode, type DemoStep } from './components/GuidedDemoMode';

const DEMO_STEPS_CONFIG: Omit<DemoStep, 'onExecute'>[] = [
    {
        id: 1,
        scenario: '🍺 Liquor Store',
        title: 'Age Verification — Zero Knowledge',
        description:
            'A liquor store scans your wallet QR. miTch evaluates the request against ' +
            'your policy. The store is trusted and only asks for proof of age ≥ 18. ' +
            'No consent dialog needed — miTch auto-approves because the rule already covers this.',
        whatVerifierSees: '✅ age ≥ 18: true (proof only)',
        whatIsBlocked: '❌ birthDate  ❌ name  ❌ address',
        buttonId: 'btn-liquor-store',
        expectedVerdict: 'ALLOW'
    },
    {
        id: 2,
        scenario: '🏥 Doctor Login',
        title: 'Multi-Credential — Consent Required',
        description:
            'A hospital portal requests your ID (age ≥ 18) and medical license. ' +
            'miTch finds a matching rule but flags it for explicit consent — ' +
            'two credential types, professional data. You must approve.',
        whatVerifierSees: '✅ age ≥ 18  ✅ role: Physician  ✅ licenseId',
        whatIsBlocked: '❌ birthDate  ❌ salary  ❌ home address',
        buttonId: 'btn-doctor-login',
        expectedVerdict: 'PROMPT'
    },
    {
        id: 3,
        scenario: '🚑 EHDS Emergency Room',
        title: 'Health Data — Biometric Binding Required',
        description:
            'A Spanish ER requests your patient summary (blood group, allergies). ' +
            'This is Layer 2 data — the highest protection tier. miTch requires ' +
            'explicit consent AND biometric presence (WebAuthn). ' +
            'The Approve button stays locked until your fingerprint/PIN confirms presence.',
        whatVerifierSees: '✅ bloodGroup  ✅ allergies  ✅ emergencyContacts',
        whatIsBlocked: '❌ diagnosis history  ❌ genetic data  ❌ insuranceId',
        buttonId: 'btn-ehds-er',
        expectedVerdict: 'PROMPT+BIOMETRIC'
    },
    {
        id: 4,
        scenario: '💊 Pharmacy',
        title: 'ePrescription — Time-Limited Disclosure',
        description:
            'A pharmacy requests your prescription details. The credential is only ' +
            'valid for 30 days (freshness policy). After approval, the session key is ' +
            'destroyed immediately — Crypto-Shredding in action.',
        whatVerifierSees: '✅ medication  ✅ dosageInstruction  ✅ refillsRemaining',
        whatIsBlocked: '❌ diagnosis  ❌ genetic data  ❌ insuranceId',
        buttonId: 'btn-pharmacy',
        expectedVerdict: 'PROMPT'
    }
];

export default function App() {
    const [status, setStatus] = useState<string>('LOCKED');
    const [logs, setLogs] = useState<string[]>([]);
    const [evaluationResult, setEvaluationResult] = useState<PolicyEvaluationResult | null>(null);
    const [showConsent, setShowConsent] = useState(false);
    const [currentPolicy, setCurrentPolicy] = useState<PolicyManifest | null>(null);
    const [currentRequest, setCurrentRequest] = useState<VerifierRequest | null>(null); // T-28: Store pending request for override
    const [showPrivacyAudit, setShowPrivacyAudit] = useState(false);
    const [_privacyConsent, setPrivacyConsent] = useState<PrivacyConsent | null>(null);
    const [guidedDemoActive, setGuidedDemoActive] = useState<boolean>(
        () => !sessionStorage.getItem('guidedDemoCompleted')
    );

    // Service Instance
    const walletRef = useRef<WalletService>(new WalletService());

    const addLog = (msg: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
        const time = new Date().toLocaleTimeString();
        setLogs(prev => [...prev, `${type.toUpperCase()}|${time} | ${msg}`]);
    };

    // Auto-init for Demo
    useEffect(() => {
        const init = async () => {
            addLog('🔐 Initializing Wallet Service...', 'info');
            try {
                // In production, this PIN comes from user input
                await walletRef.current.initialize("123456");
                addLog('🔓 Wallet Decrypted & Ready', 'success');
                setCurrentPolicy(walletRef.current.getPolicy());

                // --- WebAuthn Auto-Registration Hook ---
                try {
                    const isAvailable = await WebAuthnService.isAvailable();
                    const isRegistered = await WebAuthnService.isRegistered();
                    if (isAvailable && !isRegistered) {
                        addLog('📱 No Passkey found. Attempting Auto-Registration...', 'info');
                        await WebAuthnService.registerPasskey();
                        addLog('✅ Passkey (Platform Authenticator) registered automatically.', 'success');
                    }
                } catch (authError) {
                    addLog(`⚠️  Passkey auto-registration skipped: ${authError instanceof Error ? authError.message : String(authError)}`, 'warning');
                }
                // ----------------------------------------

                setStatus('IDLE');
            } catch (e) {
                console.error(e);
                const message = e instanceof Error ? e.message : String(e);
                addLog(`❌ Init Failed: ${message || 'Unknown error'}`, 'error');
            }
        };
        init();
    }, []);

    const handleProveAge = async () => {
        setStatus('EVALUATING');
        setLogs([]);
        setEvaluationResult(null);

        // 1. Prepare Request
        addLog(`📥 Received request from: did:mitch:verifier-liquor-store`, 'info');
        const request: VerifierRequest = {
            verifierId: 'did:mitch:verifier-liquor-store',
            requestedClaims: [], // No raw claims requested anymore (T-14)
            requestedProvenClaims: ['age >= 18'], // Simulated ZKP Request
            origin: CONFIG.VERIFIER_ENDPOINT.replace(/\/present$/, ''),
            serviceEndpoint: CONFIG.VERIFIER_ENDPOINT
        };
        setCurrentRequest(request); // T-28: Store for potential override

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

        // 2. Evaluate via Service
        addLog('⚖️ Evaluating Policy...', 'info');
        try {
            const result = await walletRef.current.evaluateRequest(request, context);
            setEvaluationResult(result);

            if (result.verdict === 'DENY') {
                setStatus('DENIED');
                addLog(`🚫 Policy BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
                return;
            }

            if (result.verdict === 'PROMPT') {
                addLog(`🔔 Consent Required: ${result.reasonCodes.join(', ')}`, 'info');
                setShowConsent(true);
                return;
            }

            // ALLOW
            addLog(`✅ Policy ALLOWED. Auto-issuing...`, 'success');
            await proceedWithProof(result, undefined, request.serviceEndpoint);
        } catch (e) {
            console.error(e);
            addLog(`❌ Evaluation Error: ${(e as Error).message}`, 'error');
            setStatus('IDLE');
        }
    };





    const proceedWithProof = async (policyResult?: PolicyEvaluationResult, targetKey?: CryptoKey, endpoint?: string) => {
        const result = policyResult || evaluationResult;

        if (!result || !result.decisionCapsule) {
            addLog('❌ No Decision Capsule found!', 'error');
            return;
        }

        // Smart Endpoint Resolution
        const targetEndpoint =
            endpoint ||
            (result.decisionCapsule as any).service_endpoint ||
            CONFIG.VERIFIER_ENDPOINT;

        setShowConsent(false);
        setStatus('PROVING');

        try {
            addLog('🔐 Generating Secure Presentation...', 'info');

            const { encryptedVp, auditLog } = await walletRef.current.generatePresentation(result.decisionCapsule, targetKey);

            auditLog.forEach(l => addLog(l, l.includes('ALERT') ? 'error' : 'info'));

            addLog(`🚀 Sending Encrypted VP to ${targetEndpoint}...`, 'info');

            try {
                const response = await fetch(targetEndpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: encryptedVp
                });

                if (response.ok) {
                    addLog('✅ Verifier acknowledged receipt', 'success');
                } else {
                    const error = await response.json();
                    addLog(`⚠️ Verifier rejected: ${error.details || error.error}`, 'warning');
                }
            } catch (e) {
                console.error("Transmission Error:", e);
                addLog(`📡 Network Error: ${(e as Error).message}. Is backend running on ${targetEndpoint}?`, 'error');
            }

            const snippet = encryptedVp.length > 50 ? encryptedVp.substring(0, 50) + '...' : encryptedVp;
            addLog(`📦 Sent: ${snippet}`, 'success');

            setLogs(prev => [...prev, 'DONE|--- PROOF COMPLETE ---']);
            setStatus('SHREDDED');
        } catch (error) {
            console.error(error);
            addLog(`❌ Proof Gen Failed: ${error instanceof Error ? error.message : 'Unknown'}`, 'error');
            setStatus('IDLE');
        }
    };

    // Privacy Audit acceptance
    const handlePrivacyAuditAccept = (context: PrivacyContext) => {
        const consent: PrivacyConsent = {
            status: 'ACCEPT',
            acceptedTrackers: context.detectedTrackers.map(t => t.actor),
            timestamp: new Date().toISOString(),
            auditHash: context.auditProof?.hash || 'unknown'
        };
        setPrivacyConsent(consent);
        setShowPrivacyAudit(false);
        addLog(`🛡️ Acknowledged tracking by: ${consent.acceptedTrackers.join(', ')}`, 'success');
        proceedWithProof(evaluationResult || undefined);
    };

    // --- Production Cleanup: Lab/Debug functions removed ---

    const handleMultiProofDemo = async () => {
        addLog('🏥 DEMO: Doctor Login (Multi-VC Bundle)...', 'warning');
        addLog('📥 Request: "Provide ID (Age>=18) AND Medical License"', 'info');

        const request: VerifierRequest = {
            verifierId: 'med-portal-login',
            origin: 'https://portal.st-mary.med',
            requirements: [
                {
                    credentialType: 'AgeCredential', // Proof of Identity
                    requestedClaims: [],
                    requestedProvenClaims: ['age >= 18']
                },
                {
                    credentialType: 'EmploymentCredential', // Proof of Profession
                    requestedClaims: ['role', 'licenseId'],
                    requestedProvenClaims: []
                }
            ]
        };

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

        const result = await walletRef.current.evaluateRequest(request, context);
        setEvaluationResult(result);

        if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
            addLog(`✅ Policy ALLOWED Multi-VC Bundle.`, 'success');
            if (result.verdict === 'PROMPT') setShowConsent(true);
            else proceedWithProof(result);
        } else {
            addLog(`🚫 Policy BLOCKED Multi-VC Request: ${result.reasonCodes.join(', ')}`, 'error');
        }
    };


    const handleWebAuthnDemo = async () => {
        addLog('🔐 DEMO: Simulating High-Risk Request (Requires Presence)...', 'warning');
        addLog('👤 Triggering Biometric Challenge (WebAuthn)...', 'info');

        const start = Date.now();
        const demoPresenceProof = await WebAuthnService.provePresence('demo-decision-456');
        const duration = Date.now() - start;

        addLog(`✅ DEMO SUCCESS: Presence Proof Generated in ${duration}ms`, 'success');
        addLog(`🛡️ Signature: ${demoPresenceProof.substring(0, 16)}...`, 'info');
        addLog('🔗 Binding: Signature is cryptographically tied to Decision ID demo-decision-456', 'info');
    };

    const handleRecoveryTest = async () => {
        addLog('🛡️ DEMO: Starting Social Recovery Setup...', 'warning');
        const fragments = await walletRef.current.splitMasterKey();
        addLog(`✅ DEMO: Master Key split into 3 fragments (Circle of Trust)`, 'success');
        fragments.forEach((f, i) => addLog(`👤 Friend ${i + 1} received: ${f.substring(0, 8)}...`, 'info'));

        addLog('🧪 DEMO: Simulating device loss... attempting recovery.', 'warning');
        await walletRef.current.recoverFromFragments(fragments);
        addLog('🏁 DEMO COMPLETE: Wallet access restored via Social Recovery.', 'success');
    };

    const handleHealthAccessDemo = async () => {
        addLog('🚑 EHDS: Simulating Hospital Emergency Access...', 'warning');
        addLog('📥 Request: "Provide Blood Type & Allergies"', 'info');

        const request: VerifierRequest = {
            verifierId: 'hospital-madrid-er-1', // Matches T-30 policy rule
            origin: 'https://er.madrid.health',
            requirements: [
                {
                    credentialType: 'PatientSummary', // Updated to match T-30a Schema
                    requestedClaims: ['bloodGroup', 'allergies'], // Updated to match T-30a Schema
                    requestedProvenClaims: []
                }
            ]
        };

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

        const result = await walletRef.current.evaluateRequest(request, context);
        setEvaluationResult(result);

        if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
            addLog(`✅ Policy ALLOWED Health Data Access.`, 'success');
            if (result.verdict === 'PROMPT') setShowConsent(true);
            else proceedWithProof(result);
        } else {
            addLog(`🚫 Policy BLOCKED Health Request: ${result.reasonCodes.join(', ')}`, 'error');
        }
    };

    const handlePharmacyDemo = async () => {
        addLog('💊 PHARMACY: Simulating Prescription Dispense...', 'warning');
        addLog('📥 Request: "Provide Medication & Dosage"', 'info');

        const request: VerifierRequest = {
            verifierId: 'pharmacy-berlin-center', // Matches T-30b policy rule
            origin: 'https://pharmacy.berlin.health',
            requirements: [
                {
                    credentialType: 'Prescription', // Specific resource type
                    requestedClaims: ['medication', 'dosageInstruction'],
                    requestedProvenClaims: []
                }
            ]
        };

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

        const result = await walletRef.current.evaluateRequest(request, context);
        setEvaluationResult(result);

        if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
            addLog(`✅ Policy ALLOWED Pharmacy Access.`, 'success');
            if (result.verdict === 'PROMPT') setShowConsent(true);
            else proceedWithProof(result);
        } else {
            addLog(`🚫 Policy BLOCKED Pharmacy Request: ${result.reasonCodes.join(', ')}`, 'error');
        }
    };

    const handleResearchDemo = async () => {
        addLog('🔬 RESEARCH: Simulating Secondary-Use Data Request...', 'warning');
        addLog('📥 Request: "Provide Blood Group & Allergies for research"', 'info');

        const request: VerifierRequest = {
            verifierId: 'did:eu:research-institute-fhi',
            origin: 'https://research.fhi.eu',
            usagePurpose: 'researchSecondary' as any,
            requirements: [{
                credentialType: 'PatientSummary',
                requestedClaims: ['bloodGroup', 'allergies'],
                requestedProvenClaims: []
            }]
        };

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

        const result = await walletRef.current.evaluateRequest(request, context);
        setEvaluationResult(result);

        if (result.verdict === 'DENY') {
            setStatus('DENIED');
            addLog(`🚫 Secondary Use BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
            return;
        }
        if (result.verdict === 'PROMPT') {
            addLog(`🔔 Research Consent Required: ${result.reasonCodes.join(', ')}`, 'info');
            setShowConsent(true);
            return;
        }
        addLog(`✅ Research Access ALLOWED`, 'success');
        await proceedWithProof(result);
    };

    const handleCrossBorderDemo = async () => {
        addLog('🇪🇸 CROSS-BORDER: Spanish Hospital Emergency...', 'warning');
        addLog('📥 Request: "Provide Blood Type & Allergies (Cross-Border EU)"', 'info');

        const request: VerifierRequest = {
            verifierId: 'did:es:hospital-barcelona-er-1',
            origin: 'https://er.barcelona.health',
            requirements: [{
                credentialType: 'PatientSummary',
                requestedClaims: ['bloodGroup', 'allergies'],
                requestedProvenClaims: []
            }]
        };

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

        const result = await walletRef.current.evaluateRequest(request, context);
        setEvaluationResult(result);

        if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
            addLog(`✅ Cross-Border Access via GDPR Art. 1`, 'success');
            if (result.verdict === 'PROMPT') setShowConsent(true);
            else await proceedWithProof(result);
        } else {
            addLog(`🚫 Cross-Border BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
        }
    };

    const renderLogLine = (l: string, i: number) => {
        if (l.startsWith('DONE')) return <div key={i} style={{ marginTop: 10, borderTop: '1px solid #333', paddingTop: 5, color: '#888' }}>{l.split('|')[1]}</div>;
        const parts = l.split('|');
        if (parts.length < 3) return <div key={i}>{l}</div>;

        const type = parts[0];
        const time = parts[1];
        const msg = parts.slice(2).join('|');
        const className = `audit-${type.toLowerCase()}`;

        return (
            <div key={i} className={className} style={{ marginBottom: 4, display: 'flex', gap: '8px' }}>
                <span style={{ color: '#666', minWidth: '60px' }}>{time}</span>
                <span>{msg}</span>
            </div>
        );
    };

    return (
        <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            minHeight: '100vh',
            padding: 20
        }}>
            <h1 style={{ marginBottom: 10 }}>miTch <span style={{ fontWeight: 800, color: '#0070f3' }}>Smart Wallet</span></h1>

            <div style={{
                background: '#1a1a1a',
                padding: 20,
                borderRadius: 16,
                border: '1px solid #333',
                width: '100%',
                maxWidth: 400,
                marginBottom: 30
            }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                    <span style={{ color: '#888', fontSize: 12 }}>Active Credential</span>
                    <span style={{ background: '#2e7d32', padding: '2px 6px', borderRadius: 4, fontSize: 10 }}>TRUSTED</span>
                </div>
                <div style={{ fontSize: 18, fontWeight: 600 }}>Age Credential (GovID)</div>
                <div style={{ color: '#00bfff', fontSize: 14 }}>Issued by: did:example:gov-issuer</div>
                <div style={{ height: 10 }}></div>
                <div style={{ fontSize: 18, fontWeight: 600 }}>Hospital ID</div>
                <div style={{ color: '#00bfff', fontSize: 14 }}>Issued by: did:example:st-mary-hospital</div>
            </div>

            {/* T-24: Secure Decision Boundary (Human-in-the-Loop) */}
            {showConsent && evaluationResult?.decisionCapsule && (
                <ConsentModal
                    capsule={evaluationResult.decisionCapsule}
                    reasonCodes={evaluationResult.reasonCodes}
                    timeoutMinutes={currentPolicy?.globalSettings?.requireConsentTimeoutMinutes}
                    onApprove={(_presenceProof) => {
                        setShowConsent(false);
                        proceedWithProof(evaluationResult, undefined, currentRequest?.serviceEndpoint);
                    }}
                    onReject={() => {
                        setStatus('DENIED');
                        addLog('🚫 User rejected via Secure UI', 'error');
                        setShowConsent(false);
                    }}
                    onLog={addLog}
                />
            )}

            {/* T-28: Smart Denial & Recovery Modal */}
            {status === 'DENIED' && evaluationResult?.denialResolution && (
                <div className="secure-backdrop">
                    <div className="secure-prompt" style={{ borderTop: `4px solid ${evaluationResult.denialResolution.severity === 'CRITICAL' ? '#E53935' : '#F57C00'}` }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 15 }}>
                            <div style={{ fontSize: 24 }}>
                                {evaluationResult.denialResolution.severity === 'CRITICAL' ? '⛔' : '⚠️'}
                            </div>
                            <h2 style={{ fontSize: 20, margin: 0 }}>
                                {evaluationResult.denialResolution.title}
                            </h2>
                        </div>

                        <p style={{ color: '#ccc', fontSize: 16, lineHeight: 1.5, marginBottom: 25 }}>
                            {evaluationResult.denialResolution.message}
                        </p>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            {evaluationResult.denialResolution.actions.map(action => (
                                <button
                                    key={action.id}
                                    onClick={async () => {
                                        addLog(`👉 User triggered: ${action.label}`, 'info');
                                        const actionResult = await walletRef.current.handleAction(action);
                                        if (actionResult.success) {
                                            addLog(`✅ Action Completed: ${actionResult.message}`, 'success');

                                            if (action.type === 'OVERRIDE_WITH_CONSENT') {
                                                // Re-evaluate the original request with override context
                                                // This generates a valid decisionCapsule
                                                addLog('🔄 Re-evaluating with override permission...', 'info');

                                                if (!currentRequest) {
                                                    addLog('❌ Error: Original request lost from context.', 'error');
                                                    setStatus('DENIED');
                                                    return;
                                                }

                                                const overrideResult = await walletRef.current.evaluateRequest(
                                                    currentRequest,
                                                    { timestamp: Date.now(), userDID: 'did:example:wallet-user', overrideGranted: true }
                                                );

                                                if (overrideResult.decisionCapsule) {
                                                    setEvaluationResult(overrideResult);
                                                    setShowConsent(true);
                                                } else {
                                                    addLog('❌ Override failed: Could not generate proof authorization', 'error');
                                                    setStatus('DENIED');
                                                }
                                            } else {
                                                // Auto-recovery to IDLE after successful action
                                                setTimeout(() => {
                                                    setStatus('IDLE');
                                                    addLog('🔄 Wallet ready for new transaction', 'info');
                                                }, 1500);
                                            }
                                        }
                                    }}
                                    style={{
                                        padding: 14,
                                        background: action.type === 'OVERRIDE_WITH_CONSENT' ? '#E53935' : '#333',
                                        border: '1px solid #444',
                                        borderRadius: 8,
                                        color: '#fff',
                                        cursor: 'pointer',
                                        fontSize: 14,
                                        fontWeight: 600,
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center'
                                    }}
                                >
                                    <span>{action.label}</span>
                                    {action.type === 'LEARN_MORE' && <span>↗</span>}
                                </button>
                            ))}
                            <button
                                onClick={() => setStatus('IDLE')}
                                style={{
                                    padding: 14,
                                    background: 'transparent',
                                    border: 'none',
                                    color: '#666',
                                    cursor: 'pointer',
                                    fontSize: 14
                                }}
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Privacy Audit / Transparency Layer */}
            {showPrivacyAudit && evaluationResult && (
                <PrivacyAuditModal
                    verifierName={evaluationResult.decisionCapsule?.verifier_did || 'Unknown Verifier'}
                    onAccept={(context) => handlePrivacyAuditAccept(context)}
                    onCancel={() => {
                        setShowPrivacyAudit(false);
                        // Re-open Consent to prevent lost state
                        setShowConsent(true);
                        addLog('� Privacy Audit cancelled, returning to Consent', 'warning');
                    }}
                />
            )}

            <button
                id="btn-liquor-store"
                onClick={() => {
                    if (status === 'SHREDDED') {
                        setStatus('IDLE');
                        setEvaluationResult(null);
                        setLogs([]);
                        addLog('♻️ Wallet Memory Shredded. Ready.', 'info');
                    } else {
                        handleProveAge();
                    }
                }}
                disabled={status === 'EVALUATING' || status === 'PROVING' || status === 'LOCKED'}
                style={{
                    width: '100%', maxWidth: 400,
                    padding: 18,
                    background: status === 'DENIED' ? '#ff4444' : (status === 'SHREDDED' ? '#333' : 'linear-gradient(135deg, #0070f3 0%, #00a6ed 100%)'),
                    color: '#fff', border: 'none', borderRadius: 12,
                    fontSize: 18, fontWeight: 600,
                    cursor: 'pointer',
                    opacity: status === 'LOCKED' ? 0.7 : 1
                }}
            >
                {status === 'LOCKED' ? '🔒 Unlocking...' :
                    status === 'EVALUATING' ? '⚖️ Judging...' :
                        status === 'PROVING' ? '🔐 Generating...' :
                            status === 'SHREDDED' ? 'Done (Forgotten)' :
                                status === 'DENIED' ? '🚫 Access Denied' :
                                    '🔞 Prove Age & Forget'}
            </button>

            {evaluationResult && (
                <div className='policy-debug'>
                    <h4>🧠 Policy Engine Debug</h4>
                    <pre>
                        {JSON.stringify(evaluationResult, null, 2)}
                    </pre>
                </div>
            )}

            <div style={{ width: '100%', maxWidth: 400, marginTop: 20 }}>
                <h3 style={{ fontSize: 14, color: '#666', borderBottom: '1px solid #333', paddingBottom: 8 }}>Immutable Audit Trace</h3>
                <div style={{
                    fontFamily: 'monospace', fontSize: 12,
                    background: '#0a0a0a', padding: 15, borderRadius: 8,
                    border: '1px solid #222', minHeight: 150
                }}>
                    {logs.map(renderLogLine)}
                </div>
            </div>

            <div style={{ width: '100%', maxWidth: 400 }}>
                <ComplianceDashboard
                    onExport={useCallback(() => walletRef.current.exportAuditReport(), [])}
                    onSyncL2={useCallback(() => walletRef.current.syncAuditToL2(), [])}
                    getRecentLogs={useCallback(() => walletRef.current.getRecentAuditLogs(), [])}
                    getChainStatus={useCallback(() => walletRef.current.verifyAuditChain(), [])}
                />
            </div>

            <div style={{ width: '100%', maxWidth: 400, marginBottom: 20 }}>
                {currentPolicy && (
                    <PolicyEditor
                        policy={currentPolicy}
                        onSave={(p) => {
                            walletRef.current.savePolicy(p);
                            setCurrentPolicy(p);
                            addLog('⚖️ User Policy updated and persisted', 'success');
                        }}
                    />
                )}
            </div>

            <div style={{
                width: '100%', maxWidth: 400, marginBottom: 50, padding: 20,
                background: '#111', borderRadius: 24, border: '1px solid #333'
            }}>
                <h3 style={{ margin: '0 0 15px 0', fontSize: 16, color: '#fff' }}>🚀 Advanced Feature Demos</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <button
                        id="btn-doctor-login"
                        onClick={handleMultiProofDemo}
                        style={{ padding: 12, background: '#0891b2', border: '1px solid #0e7490', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer', gridColumn: 'span 2' }}
                    >
                        Dr. Login (High Assurance Multi-VC)
                    </button>
                    <button
                        onClick={handleWebAuthnDemo}
                        style={{ padding: 12, background: '#a21caf', border: '1px solid #c026d3', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer' }}
                    >
                        Biometric Presence (T-23)
                    </button>
                    <button
                        onClick={handleRecoveryTest}
                        style={{ padding: 12, background: '#065f46', border: '1px solid #047857', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer' }}
                    >
                        Social Recovery (T-28)
                    </button>
                    <button
                        id="btn-ehds-er"
                        onClick={handleHealthAccessDemo}
                        style={{ padding: 12, background: '#be123c', border: '1px solid #fb7185', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer' }}
                    >
                        EHDS: ER (T-30a)
                    </button>
                    <button
                        id="btn-pharmacy"
                        onClick={handlePharmacyDemo}
                        style={{ padding: 12, background: '#059669', border: '1px solid #10b981', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer' }}
                    >
                        EHDS: Pharmacy (T-30b)
                    </button>
                    <div style={{ width: '100%', gridColumn: 'span 2', marginTop: 10, marginBottom: 5, color: '#888', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
                        EHDS Scenarios
                    </div>
                    <button
                        onClick={handleResearchDemo}
                        disabled={status !== 'IDLE'}
                        style={{ padding: 12, background: '#7B1FA2', border: 'none', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}
                    >
                        🔬 Research: Patient Data
                    </button>
                    <button
                        onClick={handleCrossBorderDemo}
                        disabled={status !== 'IDLE'}
                        style={{ padding: 12, background: '#00695C', border: 'none', borderRadius: 12, color: '#fff', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}
                    >
                        🇪🇸 Cross-Border: Barcelona ER
                    </button>
                </div>
            </div>

            {status === 'IDLE' && !guidedDemoActive && (
                <button
                    onClick={() => {
                        sessionStorage.removeItem('guidedDemoCompleted');
                        setGuidedDemoActive(true);
                    }}
                    style={{
                        width: '100%',
                        maxWidth: 400,
                        padding: '10px 18px',
                        marginBottom: 12,
                        background: 'transparent',
                        border: '1px solid #333',
                        borderRadius: 10,
                        color: '#666',
                        cursor: 'pointer',
                        fontSize: 13
                    }}
                >
                    ▶ Start Guided Demo
                </button>
            )}

            <GuidedDemoMode
                isActive={guidedDemoActive && status === 'IDLE'}
                onExit={() => setGuidedDemoActive(false)}
                onStepExecute={(_stepId) => { }}
                steps={DEMO_STEPS_CONFIG.map(s => ({
                    ...s,
                    onExecute: s.id === 1 ? handleProveAge
                        : s.id === 2 ? handleMultiProofDemo
                            : s.id === 3 ? handleHealthAccessDemo
                                : handlePharmacyDemo
                }))}
            />
        </div>
    );

}
