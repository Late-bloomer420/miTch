import { useState, useEffect, useRef, useCallback } from 'react';
import './App.css';
import './wallet.css';

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
import {
    buildSDJWTPresentation,
    validateSDJWTPresentation,
    buildSessionCleanup,
    SCENARIO_VCT,
    type AuthorizationRequest,
} from '@mitch/oid4vp';
import { SCENARIO_CLAIMS } from './scenario-claims';

const DEMO_STEPS_CONFIG: Omit<DemoStep, 'onExecute'>[] = [
    {
        id: 1,
        scenario: '🍺 Age Check',
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
        scenario: '🚑 EHDS Emergency',
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
    const [currentRequest, setCurrentRequest] = useState<VerifierRequest | null>(null);
    const [showPrivacyAudit, setShowPrivacyAudit] = useState(false);
    const [_privacyConsent, setPrivacyConsent] = useState<PrivacyConsent | null>(null);
    const [guidedDemoActive, setGuidedDemoActive] = useState<boolean>(
        () => !sessionStorage.getItem('guidedDemoCompleted')
    );
    const [showSecondary, setShowSecondary] = useState(false);
    const [flashAllow, setFlashAllow] = useState(false);
    const [copyLabel, setCopyLabel] = useState('Copy Log');
    const [credentialStatus, setCredentialStatus] = useState<'idle' | 'fetching' | 'done' | 'error'>('idle');

    // Parse OID4VP deep-link params on load (verifier-demo → wallet-pwa)
    const [incomingOID4VP] = useState<{ scenario: string; endpoint: string; verifier: string } | null>(() => {
        try {
            const p = new URLSearchParams(window.location.search);
            const endpoint = p.get('endpoint');
            const scenario = p.get('scenario');
            if (!endpoint || !scenario) return null;
            return { scenario, endpoint, verifier: p.get('verifier') ?? 'did:mitch:verifier-liquor-store' };
        } catch { return null; }
    });

    const logContainerRef = useRef<HTMLDivElement>(null);
    const walletRef = useRef<WalletService>(new WalletService());

    const addLog = (msg: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
        const time = new Date().toLocaleTimeString();
        setLogs(prev => [...prev, `${type.toUpperCase()}|${time} | ${msg}`]);
    };

    // Auto-scroll Audit Log (UX-05)
    useEffect(() => {
        if (logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
        }
    }, [logs]);

    // Auto-init for Demo
    useEffect(() => {
        const init = async () => {
            addLog('🔐 Initializing Wallet Service...', 'info');
            try {
                await walletRef.current.initialize("123456");
                addLog('🔓 Wallet Decrypted & Ready', 'success');
                setCurrentPolicy(walletRef.current.getPolicy());

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
        setFlashAllow(false);

        addLog(`📥 Received request from: did:mitch:verifier-liquor-store`, 'info');
        const request: VerifierRequest = {
            verifierId: 'did:mitch:verifier-liquor-store',
            requestedClaims: [],
            requestedProvenClaims: ['age >= 18'],
            origin: CONFIG.VERIFIER_ENDPOINT.replace(/\/present$/, ''),
            serviceEndpoint: CONFIG.VERIFIER_ENDPOINT
        };
        setCurrentRequest(request);

        const context: EvaluationContext = {
            timestamp: Date.now(),
            userDID: 'did:example:wallet-user'
        };

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
            setFlashAllow(true);
            setTimeout(() => setFlashAllow(false), 900);
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

        const targetEndpoint =
            endpoint ||
            (result.decisionCapsule as unknown as Record<string, unknown>).service_endpoint as string | undefined ||
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

    const handleMultiProofDemo = async () => {
        addLog('🏥 DEMO: Doctor Login (Multi-VC Bundle)...', 'warning');
        addLog('📥 Request: "Provide ID (Age>=18) AND Medical License"', 'info');

        const request: VerifierRequest = {
            verifierId: 'med-portal-login',
            origin: 'https://portal.st-mary.med',
            requirements: [
                {
                    credentialType: 'AgeCredential',
                    requestedClaims: [],
                    requestedProvenClaims: ['age >= 18']
                },
                {
                    credentialType: 'EmploymentCredential',
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
            verifierId: 'hospital-madrid-er-1',
            origin: 'https://er.madrid.health',
            requirements: [
                {
                    credentialType: 'PatientSummary',
                    requestedClaims: ['bloodGroup', 'allergies'],
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
            verifierId: 'pharmacy-berlin-center',
            origin: 'https://pharmacy.berlin.health',
            requirements: [
                {
                    credentialType: 'Prescription',
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
            usagePurpose: 'researchSecondary',
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

    // UX-05: Render log with slide-in animation (key includes index for animation re-trigger)
    const renderLogLine = (l: string, i: number) => {
        if (l.startsWith('DONE')) return (
            <div key={i} className="audit-log-done">{l.split('|')[1]}</div>
        );
        const parts = l.split('|');
        if (parts.length < 3) return <div key={i}>{l}</div>;

        const type = parts[0];
        const time = parts[1];
        const msg = parts.slice(2).join('|');
        const className = `audit-${type.toLowerCase()} audit-log-entry`;

        return (
            <div key={i} className={className}>
                <span className="audit-log-time">{time}</span>
                <span className="audit-log-msg">{msg}</span>
            </div>
        );
    };

    // UX-05: Copy log to clipboard
    const handleCopyLog = () => {
        const text = logs.map(l => {
            const parts = l.split('|');
            return parts.length >= 3
                ? `[${parts[1]}] ${parts.slice(2).join('|')}`
                : l;
        }).join('\n');
        navigator.clipboard.writeText(text).then(() => {
            setCopyLabel('Copied!');
            setTimeout(() => setCopyLabel('Copy Log'), 2000);
        });
    };

    // OID4VP: present SD-JWT VP to verifier via direct_post
    const presentOID4VP = async (authRequest: AuthorizationRequest, scenarioId: string) => {
        let holderKeys: CryptoKeyPair | null = null;
        let issuerKeys: CryptoKeyPair | null = null;

        try {
            setStatus('PROVING');
            addLog('🔐 Generating SD-JWT Verifiable Presentation...', 'info');

            // Generate ephemeral key pairs (PoC — in production, holder key is from wallet, issuer from trust registry)
            holderKeys = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
            );
            issuerKeys = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
            );

            const claims = SCENARIO_CLAIMS[scenarioId] ?? SCENARIO_CLAIMS['liquor-store'];
            const isRevoked = scenarioId === 'revoked';

            // W-03: Build SD-JWT VP Token with Key Binding JWT
            const { vpTokenString, presentationSubmission, disclosedClaims } = await buildSDJWTPresentation({
                request: authRequest,
                issuerPrivateKey: issuerKeys.privateKey,
                holderKeyPair: holderKeys,
                claims,
                vct: SCENARIO_VCT[scenarioId] ?? 'https://mitch.demo/vct/age-credential',
                issuerDid: 'https://issuer.mitch.demo',
                revoked: isRevoked,
            });

            addLog(`📋 Disclosed: ${Object.keys(disclosedClaims).join(', ')}`, 'info');
            addLog(`🔑 Key Binding JWT attached (nonce + aud bound)`, 'info');

            // Send issuer public key alongside VP for PoC verification
            const issuerPubJwk = await crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

            // POST direct_post to verifier redirect_uri
            const redirectUri = authRequest.redirect_uri;
            addLog(`🚀 POSTing VP to ${redirectUri}...`, 'info');

            const response = await fetch(redirectUri, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    vp_token: vpTokenString,
                    presentation_submission: presentationSubmission,
                    state: authRequest.state,
                    issuer_jwk: issuerPubJwk,
                }),
            });

            const result = await response.json() as { ok: boolean; disclosedClaims?: Record<string, unknown>; errors?: string[]; error?: string };

            if (result.ok) {
                addLog('✅ Verifier confirmed: Presentation VALID', 'success');
                if (result.disclosedClaims) {
                    addLog(`👁️ Verifier sees: ${JSON.stringify(result.disclosedClaims)}`, 'info');
                }
                setFlashAllow(true);
                setTimeout(() => setFlashAllow(false), 900);
            } else {
                addLog(`⚠️ Verifier rejected: ${result.errors?.join(', ') ?? result.error ?? 'unknown'}`, 'warning');
            }

            // W-05: Session cleanup — audit entry
            const { consentReceipt, auditEntry } = buildSessionCleanup({
                request: authRequest,
                disclosedClaims,
                outcome: result.ok ? 'SUCCESS' : 'DENIED',
            });
            addLog(`📝 Audit: ${auditEntry.outcome} — receipt ${consentReceipt.id}`, 'info');

            setLogs(prev => [...prev, 'DONE|--- OID4VP PROOF COMPLETE ---']);
            setStatus('SHREDDED');
        } catch (error) {
            addLog(`❌ OID4VP Proof Failed: ${error instanceof Error ? error.message : 'Unknown'}`, 'error');
            setStatus('IDLE');
        } finally {
            // B-03: Crypto-shredding — destroy ephemeral keys
            holderKeys = null;
            issuerKeys = null;
            addLog('🗑️ Ephemeral keys destroyed (crypto-shredding)', 'info');
        }
    };

    // OID4VP: handle incoming request from verifier-demo deep link
    const handleIncomingOID4VP = async () => {
        if (!incomingOID4VP) return;
        const { scenario, endpoint, verifier } = incomingOID4VP;

        setStatus('EVALUATING');
        setLogs([]);
        setEvaluationResult(null);
        setFlashAllow(false);

        addLog(`📲 Incoming OID4VP request from ${verifier}`, 'info');

        try {
            // Step 1: Fetch OID4VP Authorization Request from verifier
            addLog(`🔄 Fetching auth request from ${endpoint}/authorize...`, 'info');
            const authRes = await fetch(`${endpoint}/authorize?scenario=${encodeURIComponent(scenario)}`);
            if (!authRes.ok) throw new Error(`Verifier /authorize returned ${authRes.status}`);
            const { authRequest } = await authRes.json() as { authRequest: AuthorizationRequest };

            addLog(`📄 Received PD: ${authRequest.presentation_definition.name ?? authRequest.presentation_definition.id}`, 'info');

            // Step 2: Policy evaluation (convert OID4VP request to VerifierRequest for policy engine)
            const policyRequest: VerifierRequest = {
                verifierId: verifier,
                requestedClaims: authRequest.presentation_definition.input_descriptors.flatMap(
                    d => d.constraints?.fields?.flatMap(f => f.path.map(p => p.replace('$.', ''))) ?? []
                ),
                requestedProvenClaims: [],
                origin: endpoint,
            };
            setCurrentRequest(policyRequest);

            const context: EvaluationContext = { timestamp: Date.now(), userDID: 'did:example:wallet-user' };
            const result = await walletRef.current.evaluateRequest(policyRequest, context);
            setEvaluationResult(result);

            if (result.verdict === 'DENY') {
                setStatus('DENIED');
                addLog(`🚫 Policy BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
            } else if (result.verdict === 'PROMPT') {
                addLog(`🔔 Consent Required`, 'info');
                // Store auth request for use after consent
                (window as unknown as Record<string, unknown>)._pendingAuthRequest = authRequest;
                (window as unknown as Record<string, unknown>)._pendingScenario = scenario;
                setShowConsent(true);
            } else {
                addLog(`✅ Policy ALLOWED. Building SD-JWT VP...`, 'success');
                setFlashAllow(true);
                setTimeout(() => setFlashAllow(false), 900);
                await presentOID4VP(authRequest, scenario);
            }
        } catch (e) {
            addLog(`❌ OID4VP Error: ${(e as Error).message}`, 'error');
            setStatus('IDLE');
        }

        // Clear URL params so page refresh doesn't re-trigger
        window.history.replaceState({}, '', window.location.pathname);
    };

    // OID4VCI: fetch a test credential from issuer-mock
    const handleFetchCredential = async () => {
        setCredentialStatus('fetching');
        addLog('🎫 Fetching credential from issuer-mock (OID4VCI)...', 'info');
        try {
            const res = await fetch('http://localhost:3005/credential', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    credential_definition: { type: ['VerifiableCredential', 'AgeCredential'] },
                    proof: {}
                })
            });
            if (!res.ok) throw new Error(`Issuer returned ${res.status}`);
            const data = await res.json() as { credential?: string; error?: string };
            if (!data.credential) throw new Error(data.error ?? 'No credential in response');

            // Decode JWT payload (header.payload.sig)
            const parts = data.credential.split('.');
            if (parts.length < 2) throw new Error('Invalid JWT format');
            const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
            const payload = JSON.parse(payloadJson) as Record<string, unknown>;
            const vcPayload = payload['vc'] as Record<string, unknown> | undefined;
            const subject = (vcPayload?.credentialSubject ?? payload['credentialSubject'] ?? {}) as Record<string, unknown>;

            const credId = `vc-issuer-${Date.now()}`;
            await walletRef.current.addIssuedCredential(credId, subject, 'did:web:localhost%3A3005');

            setCredentialStatus('done');
            addLog(`✅ AgeCredential received from issuer-mock and stored (${credId})`, 'success');
        } catch (e) {
            setCredentialStatus('error');
            addLog(`❌ Credential fetch failed: ${(e as Error).message}`, 'error');
        }
    };

    // UX-02: primary button classes
    const getPrimaryBtnClass = () => {
        const base = 'btn-primary';
        const stateClass = {
            IDLE: 'btn-primary--idle',
            LOCKED: 'btn-primary--idle',
            EVALUATING: 'btn-primary--evaluating',
            PROVING: 'btn-primary--proving',
            SHREDDED: 'btn-primary--shredded',
            DENIED: 'btn-primary--denied',
        }[status] ?? 'btn-primary--idle';
        const flash = flashAllow ? ' btn-primary--flash-allow' : '';
        return `${base} ${stateClass}${flash}`;
    };

    const getPrimaryBtnLabel = () => {
        switch (status) {
            case 'LOCKED': return '🔒 Unlocking...';
            case 'EVALUATING': return <><span className="evaluating-spinner" />Judging...</>;
            case 'PROVING': return '🔐 Generating Proof...';
            case 'SHREDDED': return '✓ Done — Data Forgotten';
            case 'DENIED': return '🚫 Access Denied';
            default: return '🔞 Prove Age & Forget';
        }
    };

    return (
        <div className="wallet-app">
            <h1 className="wallet-title">
                miTch <span className="wallet-title-accent">Smart Wallet</span>
            </h1>

            {/* OID4VP: incoming request banner */}
            {incomingOID4VP && (
                <div style={{
                    background: 'linear-gradient(135deg, #0a1628, #0d2040)',
                    border: '1px solid #0891b2',
                    borderRadius: 10,
                    padding: '16px 20px',
                    marginBottom: 16,
                }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#38bdf8', marginBottom: 6 }}>
                        📲 Incoming Verification Request
                    </div>
                    <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>
                        Verifier: <code style={{ color: '#7dd3fc' }}>{incomingOID4VP.verifier}</code>
                    </div>
                    <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 12 }}>
                        Scenario: <code style={{ color: '#7dd3fc' }}>{incomingOID4VP.scenario}</code>
                        {' · '}Requesting: <code style={{ color: '#7dd3fc' }}>age ≥ 18</code>
                    </div>
                    <button
                        onClick={handleIncomingOID4VP}
                        disabled={status === 'EVALUATING' || status === 'PROVING' || status === 'LOCKED'}
                        style={{
                            background: '#0891b2', color: '#fff', border: 'none',
                            borderRadius: 6, padding: '8px 20px', cursor: 'pointer',
                            fontWeight: 600, fontSize: 13, marginRight: 8
                        }}
                    >
                        ✅ Accept &amp; Prove
                    </button>
                </div>
            )}

            {/* UX-03: Credential Card */}
            <div className="credential-card">
                <div className="credential-card-header">
                    <span className="credential-card-label">Active Credentials</span>
                    <span className="credential-trust-badge">✓ Trusted</span>
                </div>

                <div className="credential-item">
                    <span className="credential-icon">🪪</span>
                    <div>
                        <div className="credential-name">Age Credential (GovID)</div>
                        <div className="credential-issuer">did:example:gov-issuer</div>
                    </div>
                </div>

                <div className="credential-divider" />

                <div className="credential-item">
                    <span className="credential-icon">🏥</span>
                    <div>
                        <div className="credential-name">Hospital ID</div>
                        <div className="credential-issuer">did:example:st-mary-hospital</div>
                    </div>
                </div>

                <div className="credential-divider" />

                {/* OID4VCI: fetch credential from issuer-mock */}
                <button
                    onClick={handleFetchCredential}
                    disabled={credentialStatus === 'fetching' || status === 'LOCKED'}
                    style={{
                        width: '100%', padding: '8px 0', marginTop: 4,
                        background: credentialStatus === 'done' ? '#14532d' : '#0f172a',
                        border: `1px solid ${credentialStatus === 'done' ? '#16a34a' : '#1e3a5f'}`,
                        borderRadius: 6, color: credentialStatus === 'done' ? '#86efac' : '#7dd3fc',
                        fontSize: 12, cursor: 'pointer', fontFamily: 'monospace',
                    }}
                >
                    {credentialStatus === 'fetching' ? '⏳ Fetching…' :
                     credentialStatus === 'done' ? '✅ AgeCredential from issuer-mock' :
                     credentialStatus === 'error' ? '❌ Retry — Get Test Credential' :
                     '🎫 Get Test Credential (OID4VCI)'}
                </button>
            </div>

            {/* ConsentModal */}
            {showConsent && evaluationResult?.decisionCapsule && (
                <ConsentModal
                    capsule={evaluationResult.decisionCapsule}
                    reasonCodes={evaluationResult.reasonCodes}
                    timeoutMinutes={currentPolicy?.globalSettings?.requireConsentTimeoutMinutes}
                    onApprove={(_presenceProof) => {
                        setShowConsent(false);
                        const pendingAuth = (window as unknown as Record<string, unknown>)._pendingAuthRequest as AuthorizationRequest | undefined;
                        const pendingScenario = (window as unknown as Record<string, unknown>)._pendingScenario as string | undefined;
                        if (pendingAuth && pendingScenario) {
                            delete (window as unknown as Record<string, unknown>)._pendingAuthRequest;
                            delete (window as unknown as Record<string, unknown>)._pendingScenario;
                            presentOID4VP(pendingAuth, pendingScenario);
                        } else {
                            proceedWithProof(evaluationResult, undefined, currentRequest?.serviceEndpoint);
                        }
                    }}
                    onReject={() => {
                        setStatus('DENIED');
                        addLog('🚫 User rejected via Secure UI', 'error');
                        setShowConsent(false);
                    }}
                    onLog={addLog}
                />
            )}

            {/* Smart Denial Modal */}
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
                                                setTimeout(() => {
                                                    setStatus('IDLE');
                                                    addLog('🔄 Wallet ready for new transaction', 'info');
                                                }, 1500);
                                            }
                                        }
                                    }}
                                    className={`denial-action-btn${action.type === 'OVERRIDE_WITH_CONSENT' ? ' denial-action-btn--override' : ''}`}
                                >
                                    <span>{action.label}</span>
                                    {action.type === 'LEARN_MORE' && <span>↗</span>}
                                </button>
                            ))}
                            <button
                                onClick={() => setStatus('IDLE')}
                                className="denial-close-btn"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Privacy Audit */}
            {showPrivacyAudit && evaluationResult && (
                <PrivacyAuditModal
                    verifierName={evaluationResult.decisionCapsule?.verifier_did || 'Unknown Verifier'}
                    onAccept={(context) => handlePrivacyAuditAccept(context)}
                    onCancel={() => {
                        setShowPrivacyAudit(false);
                        setShowConsent(true);
                        addLog('🔙 Privacy Audit cancelled, returning to Consent', 'warning');
                    }}
                />
            )}

            {/* UX-02: Primary CTA Button */}
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
                className={getPrimaryBtnClass()}
            >
                {getPrimaryBtnLabel()}
            </button>

            {/* UX-02: Progress bar during PROVING */}
            {status === 'PROVING' && (
                <div className="proving-progress wallet-section">
                    <div className="proving-progress-bar" />
                </div>
            )}

            {/* UX-05: Audit Log */}
            <div className="audit-section">
                <div className="audit-header">
                    <h3 className="audit-title">Immutable Audit Trace</h3>
                    <button className="audit-copy-btn" onClick={handleCopyLog}>{copyLabel}</button>
                </div>
                <div className="audit-log-container" ref={logContainerRef}>
                    {logs.map(renderLogLine)}
                </div>
            </div>

            <div className="wallet-section" style={{ marginTop: 20 }}>
                <ComplianceDashboard
                    onExport={useCallback(() => walletRef.current.exportAuditReport(), [])}
                    onSyncL2={useCallback(() => walletRef.current.syncAuditToL2(), [])}
                    getRecentLogs={useCallback(() => walletRef.current.getRecentAuditLogs(), [])}
                    getChainStatus={useCallback(() => walletRef.current.verifyAuditChain(), [])}
                />
            </div>

            <div className="wallet-section" style={{ marginBottom: 20 }}>
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

            {/* UX-04: Demo Section with Primary / Secondary Button Hierarchy */}
            <div className="demo-section">
                <h3 className="demo-section-title">🚀 Demo Scenarios</h3>

                {/* Primary scenarios — bigger, prominent */}
                <div className="demo-primary-grid">
                    <button
                        id="btn-doctor-login"
                        onClick={handleMultiProofDemo}
                        className="btn-demo-primary btn-demo-primary--full"
                        style={{ background: 'linear-gradient(135deg, #0891b2, #0e7490)' }}
                    >
                        🏥 Doctor Login
                        <br />
                        <span style={{ fontSize: 10, opacity: 0.7, fontWeight: 400 }}>High Assurance Multi-VC</span>
                    </button>

                    <button
                        id="btn-ehds-er"
                        onClick={handleHealthAccessDemo}
                        className="btn-demo-primary"
                        style={{ background: 'linear-gradient(135deg, #be123c, #9f1239)' }}
                    >
                        🚑 ER Access
                        <br />
                        <span style={{ fontSize: 10, opacity: 0.7, fontWeight: 400 }}>EHDS Emergency</span>
                    </button>

                    <button
                        id="btn-pharmacy"
                        onClick={handlePharmacyDemo}
                        className="btn-demo-primary"
                        style={{ background: 'linear-gradient(135deg, #059669, #047857)' }}
                    >
                        💊 Pharmacy
                        <br />
                        <span style={{ fontSize: 10, opacity: 0.7, fontWeight: 400 }}>ePrescription</span>
                    </button>
                </div>

                {/* Secondary — collapsible */}
                <button
                    className="demo-secondary-toggle"
                    onClick={() => setShowSecondary(s => !s)}
                    aria-expanded={showSecondary}
                >
                    {showSecondary ? '▲ Hide' : '▼ More Demos'}
                </button>

                <div className={`demo-secondary-grid${showSecondary ? ' demo-secondary-grid--open' : ''}`}>
                    <button
                        onClick={handleWebAuthnDemo}
                        className="btn-demo-secondary"
                        style={{ borderColor: '#a21caf44', color: '#d8b4fe' }}
                    >
                        🔐 Biometric (WebAuthn)
                    </button>
                    <button
                        onClick={handleRecoveryTest}
                        className="btn-demo-secondary"
                        style={{ borderColor: '#06474444', color: '#86efac' }}
                    >
                        🛡️ Social Recovery
                    </button>
                    <button
                        onClick={handleResearchDemo}
                        disabled={status !== 'IDLE'}
                        className="btn-demo-secondary"
                    >
                        🔬 Research Data
                    </button>
                    <button
                        onClick={handleCrossBorderDemo}
                        disabled={status !== 'IDLE'}
                        className="btn-demo-secondary"
                    >
                        🇪🇸 Cross-Border
                    </button>
                </div>
            </div>

            {/* Start Guided Demo button */}
            {status === 'IDLE' && !guidedDemoActive && (
                <button
                    className="btn-start-demo"
                    onClick={() => {
                        sessionStorage.removeItem('guidedDemoCompleted');
                        setGuidedDemoActive(true);
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
