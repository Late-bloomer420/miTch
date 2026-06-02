import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './App.css';
import './wallet.css';

import { type EvaluationContext } from '@mitch/policy-engine';
import type {
  VerifierRequest,
  PolicyEvaluationResult,
  PolicyManifest,
  StoredCredentialMetadata,
} from '@mitch/shared-types';
import { WalletService } from '@mitch/wallet-core';
import { ComplianceDashboard } from './components/AuditReportPanel';
import { PolicyEditor } from './components/PolicyEditor';
import { WebAuthnService, applyJitter } from '@mitch/shared-crypto';
import { PrivacyAuditModal } from './components/PrivacyAuditModal';
import { PrivacyContext, PrivacyConsent } from './services/PrivacyAuditService';
import { ConsentModal } from './components/ConsentModal';
import { PopupBlockedModal } from './components/PopupBlockedModal';
import { ConsentManagerPanel } from './components/ConsentManagerPanel';
import { CONFIG } from './config';
import {
  appendConsentReceiptHistory,
  loadConsentReceiptHistory,
} from './consent-manager/receipt-store';
import { GuidedDemoMode, type DemoStep } from './components/GuidedDemoMode';
import {
  buildSDJWTPresentation,
  buildSessionCleanup,
  SCENARIO_VCT,
  type AuthorizationRequest,
} from '@mitch/oid4vp';
import type { ConsentReceipt } from '@mitch/oid4vp';
import { SCENARIO_CLAIMS } from './scenario-claims';
import { DataFlowPanel } from './components/DataFlowPanel';
import { LandingPage } from './LandingPage';
import { UNIFORM_HEADERS, padPayload } from './utils/anti-fingerprinting';

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
    expectedVerdict: 'ALLOW',
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
    expectedVerdict: 'PROMPT',
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
    expectedVerdict: 'PROMPT+BIOMETRIC',
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
    expectedVerdict: 'PROMPT',
  },
];

const walletRef = { current: null as any };

function WalletApp() {
  useEffect(() => {
    document.title = 'miTch Wallet';
  }, []);

  const [status, setStatus] = useState<string>('LOCKED');
  const [logs, setLogs] = useState<string[]>([]);
  const [evaluationResult, setEvaluationResult] = useState<PolicyEvaluationResult | null>(null);
  const [showConsent, setShowConsent] = useState(false);
  const [currentPolicy, setCurrentPolicy] = useState<PolicyManifest | null>(null);
  const [currentRequest, setCurrentRequest] = useState<VerifierRequest | null>(null);
  const [showPrivacyAudit, setShowPrivacyAudit] = useState(false);
  const [showDataFlow, setShowDataFlow] = useState(false);
  const [showPopupBlocked, setShowPopupBlocked] = useState(false);
  const [blockedPopupUrl, setBlockedPopupUrl] = useState('');
  const [showConsentManager, setShowConsentManager] = useState(false);
  const [_privacyConsent, setPrivacyConsent] = useState<PrivacyConsent | null>(null);
  const [lastConsentReceipt, setLastConsentReceipt] = useState<ConsentReceipt | null>(null);
  const [consentReceiptHistory, setConsentReceiptHistory] = useState(() =>
    loadConsentReceiptHistory()
  );
  const [guidedDemoActive, setGuidedDemoActive] = useState<boolean>(
    () => !sessionStorage.getItem('guidedDemoCompleted') && import.meta.env.MODE !== 'test'
  );
  const [showSecondary, setShowSecondary] = useState(false);
  const [flashAllow, setFlashAllow] = useState(false);
  const [copyLabel, setCopyLabel] = useState('Copy Log');
  const [credentialStatus, setCredentialStatus] = useState<'idle' | 'fetching' | 'done' | 'error'>(
    'idle'
  );
  const [credentials, setCredentials] = useState<StoredCredentialMetadata[]>([]);
  const [isPasskeyAvailable, setIsPasskeyAvailable] = useState(false);
  const [isPasskeyRegistered, setIsPasskeyRegistered] = useState(false);

  const internalWalletRef = useRef<WalletService | null>(null);
  walletRef.current = internalWalletRef.current;

  const loadWalletCredentials = async () => {
    if (!internalWalletRef.current) return;
    try {
      const creds = await internalWalletRef.current.getCredentials();
      setCredentials(creds);
    } catch (e) {
      console.warn('Failed loading credentials', e);
    }
  };

  // G-120: Listen for Auth Popup messages from opener window
  useEffect(() => {
    const handleOpenerMessage = (event: MessageEvent) => {
      if (event.data?.type === 'MITCH_OID4VP_REQUEST') {
        addLog('📨 Received OID4VP request via Secure Popup Bridge', 'info');
        const { scenario, endpoint, verifier } = event.data;
        handleIncomingOID4VP({ scenario, endpoint, verifier });
      }
    };

    window.addEventListener('message', handleOpenerMessage);
    
    if (window.opener) {
      window.opener.postMessage({ type: 'MITCH_WALLET_READY' }, '*');
    }

    return () => window.removeEventListener('message', handleOpenerMessage);
  }, []);

  const [incomingOID4VP] = useState<{
    scenario: string;
    endpoint: string;
    verifier: string;
  } | null>(() => {
    try {
      const p = new URLSearchParams(window.location.search);
      const endpoint = p.get('endpoint');
      const scenario = p.get('scenario');
      if (!endpoint || !scenario) return null;
      return {
        scenario,
        endpoint,
        verifier: p.get('verifier') ?? 'did:mitch:verifier-liquor-store',
      };
    } catch {
      return null;
    }
  });

  // OID4VP: Auto-trigger on load if deep-link params present
  useEffect(() => {
    if (incomingOID4VP && status === 'IDLE') {
      handleIncomingOID4VP();
    }
  }, [incomingOID4VP, status]);

  const recentAuditEntries = useMemo(() => {
    if (!internalWalletRef.current) return [];
    return internalWalletRef.current.getRecentAuditLogs(200);
  }, [logs]);

  const addLog = (msg: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `${type.toUpperCase()}|${time} | ${msg}`]);
  };

  const logContainerRef = useRef<HTMLDivElement>(null);
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
        const available = await WebAuthnService.isAvailable();
        const registered = await WebAuthnService.isRegistered();
        setIsPasskeyAvailable(available);
        setIsPasskeyRegistered(registered);

        // Modular Factory: uses decoupled storage & repositories
        const wallet = await WalletService.createBrowserWallet('123456', 'mitch-salt-v1');
        internalWalletRef.current = wallet;
        walletRef.current = wallet;

        if (available && registered) {
          setStatus('LOCKED_PASSKEY');
          addLog('📱 Passkey found. Biometric unlock available.', 'info');
        } else {
          await wallet.initialize();
          addLog('🔓 Wallet Decrypted & Ready (Modular Architecture)', 'success');
          setCurrentPolicy(wallet.getPolicy());
          await loadWalletCredentials();
          setStatus('IDLE');
        }
      } catch (e) {
        console.error(e);
        addLog(`❌ Init Failed: ${e instanceof Error ? e.message : String(e)}`, 'error');
      }
    };
    init();
  }, []);

  const handlePasskeyUnlock = async () => {
    try {
      setStatus('UNLOCKING');
      addLog('👤 Requesting Biometric Verification...', 'info');
      await WebAuthnService.provePresence('mitch-wallet-unlock');
      
      const wallet = internalWalletRef.current;
      if (!wallet) throw new Error('Wallet not created');
      
      await wallet.initialize(); 
      addLog('🔓 Passkey Verified. Wallet Ready.', 'success');
      setCurrentPolicy(wallet.getPolicy());
      await loadWalletCredentials();
      setStatus('IDLE');
    } catch (e) {
      addLog(`❌ Unlock Failed: ${e instanceof Error ? e.message : String(e)}`, 'error');
      setStatus('LOCKED_PASSKEY');
    }
  };

  const handleProveAge = async () => {
    if (!internalWalletRef.current) return;
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
      serviceEndpoint: CONFIG.VERIFIER_ENDPOINT,
    };
    setCurrentRequest(request);

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
    };

    addLog('⚖️ Evaluating Policy...', 'info');
    const result = await internalWalletRef.current.evaluateRequest(request, context);
    setEvaluationResult(result);

    if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
      addLog(`✅ Policy ALLOWED Age Verification.`, 'success');
      if (result.verdict === 'PROMPT') setShowConsent(true);
      else await proceedWithProof(result, undefined, request.serviceEndpoint);
    } else {
      addLog(`🚫 Policy BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
      setStatus('IDLE');
    }
  };

  const proceedWithProof = async (
    result?: PolicyEvaluationResult,
    targetKey?: CryptoKey,
    manualEndpoint?: string
  ) => {
    if (!result || !result.decisionCapsule || !internalWalletRef.current) return;

    setStatus('SENDING');
    const targetEndpoint = manualEndpoint || currentRequest?.serviceEndpoint || CONFIG.VERIFIER_ENDPOINT;

    try {
      addLog('🔐 Generating Secure Presentation...', 'info');

      const { encryptedVp, auditLog } = await internalWalletRef.current.generatePresentation(
        result.decisionCapsule,
        targetKey
      );

      auditLog.forEach((l: string) => addLog(l, l.includes('ALERT') ? 'error' : 'info'));

      addLog(`🚀 Sending Encrypted VP to ${targetEndpoint}...`, 'info');

      // U-22/U-23: Apply Anti-Fingerprinting (Padding + Jitter + Uniform Headers)
      const paddedPayload = padPayload(encryptedVp);
      addLog(`🛡️ Payload padded to ${paddedPayload.length} bytes (Uniformity)`, 'info');
      
      await applyJitter(20, 100);
      addLog('🛡️ Applied timing jitter (Side-channel protection)', 'info');

      try {
        const response = await fetch(targetEndpoint, {
          method: 'POST',
          headers: UNIFORM_HEADERS,
          body: paddedPayload,
        });

        if (response.ok) {
          addLog('✅ Verifier acknowledged receipt', 'success');
        } else {
          const error = await response.json();
          addLog(`⚠️ Verifier rejected: ${error.details || error.error}`, 'warning');
        }
      } catch (e) {
        console.error('Transmission Error:', e);
        addLog(
          `📡 Network Error: ${(e as Error).message}. Is backend running on ${targetEndpoint}?`,
          'error'
        );
      }

      const snippet = encryptedVp.length > 50 ? encryptedVp.substring(0, 50) + '...' : encryptedVp;
      addLog(`📦 Sent: ${snippet}`, 'success');

      setLogs((prev) => [...prev, 'DONE|--- PROOF COMPLETE ---']);
      setStatus('SHREDDED');
      setShowConsentManager(true);
    } catch (error) {
      console.error(error);
      addLog(`❌ Proof Gen Failed: ${error instanceof Error ? error.message : 'Unknown'}`, 'error');
      setStatus('IDLE');
    }
  };

  const handlePrivacyAuditAccept = async (context: PrivacyContext) => {
    const consent: PrivacyConsent = {
      status: 'ACCEPT',
      acceptedTrackers: context.detectedTrackers.map((t) => t.actor),
      timestamp: new Date().toISOString(),
      auditHash: context.auditProof?.hash || 'unknown',
    };
    setPrivacyConsent(consent);
    setShowPrivacyAudit(false);
    addLog(`🛡️ Acknowledged tracking by: ${consent.acceptedTrackers.join(', ')}`, 'success');

    try {
      if (internalWalletRef.current) {
        const capsule = evaluationResult?.decisionCapsule;
        const entries = await internalWalletRef.current.recordIdentityFirewallEvents(
            capsule?.decision_id,
            capsule?.verifier_did,
            context.detectedTrackers
        );
        if (entries.length > 0) {
            addLog(`🛡️ Identity Firewall logged ${entries.length} transparency events`, 'info');
        }
      }
    } catch (error) {
      console.warn('[IdentityFirewall] Failed to record transparency events:', error);
      addLog('⚠️ Identity Firewall logging unavailable; continuing proof flow', 'warning');
    }

    await proceedWithProof(evaluationResult || undefined);
  };

  const handleMultiProofDemo = async () => {
    if (!internalWalletRef.current) return;
    addLog('🏥 DEMO: Doctor Login (Multi-VC Bundle)...', 'warning');
    addLog('📥 Request: "Provide ID (Age>=18) AND Medical License"', 'info');

    const request: VerifierRequest = {
      verifierId: 'med-portal-login',
      origin: 'https://portal.st-mary.med',
      requirements: [
        {
          credentialType: 'AgeCredential',
          requestedClaims: [],
          requestedProvenClaims: ['age >= 18'],
        },
        {
          credentialType: 'EmploymentCredential',
          requestedClaims: ['role', 'licenseId'],
          requestedProvenClaims: [],
        },
      ],
    };

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
    };

    const result = await internalWalletRef.current.evaluateRequest(request, context);
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
    addLog(
      '🔗 Binding: Signature is cryptographically tied to Decision ID demo-decision-456',
      'info'
    );
  };

  const handleRecoveryTest = async () => {
    if (!internalWalletRef.current) return;
    addLog('🛡️ DEMO: Starting Social Recovery Setup...', 'warning');
    const fragments = await internalWalletRef.current.splitMasterKey();
    addLog(`✅ DEMO: Master Key split into 3 fragments (Circle of Trust)`, 'success');
    fragments.forEach((f: string, i: number) =>
      addLog(`👤 Friend ${i + 1} received: ${f.substring(0, 8)}...`, 'info')
    );

    addLog('🧪 DEMO: Simulating device loss... attempting recovery.', 'warning');
    await internalWalletRef.current.recoverFromFragments(fragments);
    addLog('🏁 DEMO COMPLETE: Wallet access restored via Social Recovery.', 'success');
  };

  const handleHealthAccessDemo = async () => {
    if (!internalWalletRef.current) return;
    addLog('🚑 EHDS: Simulating Hospital Emergency Access...', 'warning');
    addLog('📥 Request: "Provide Blood Type & Allergies"', 'info');

    const request: VerifierRequest = {
      verifierId: 'ehds-emergency-portal',
      origin: 'https://emergency.hospital.es',
      requirements: [
        {
          credentialType: 'PatientSummary',
          requestedClaims: ['bloodGroup', 'allergies', 'emergencyContacts'],
          requestedProvenClaims: [],
        },
      ],
    };

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
    };

    const result = await internalWalletRef.current.evaluateRequest(request, context);
    setEvaluationResult(result);

    if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
      addLog(`✅ Policy ALLOWED Emergency Access.`, 'success');
      if (result.verdict === 'PROMPT') setShowConsent(true);
      else proceedWithProof(result);
    } else {
      addLog(`🚫 Policy BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
    }
  };

  const handlePharmacyDemo = async () => {
    if (!internalWalletRef.current) return;
    addLog('💊 DEMO: Pharmacy ePrescription...', 'warning');
    addLog('📥 Request: "Provide active prescriptions"', 'info');

    const request: VerifierRequest = {
      verifierId: 'pharmacy-xyz',
      origin: 'https://pharmacy.xyz',
      requirements: [
        {
          credentialType: 'Prescription',
          requestedClaims: ['medication', 'dosageInstruction', 'refillsRemaining'],
          requestedProvenClaims: [],
        },
      ],
    };

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
    };

    const result = await internalWalletRef.current.evaluateRequest(request, context);
    setEvaluationResult(result);

    if (result.verdict === 'ALLOW' || result.verdict === 'PROMPT') {
      addLog(`✅ Policy ALLOWED Prescription Access.`, 'success');
      if (result.verdict === 'PROMPT') setShowConsent(true);
      else await proceedWithProof(result);
    } else {
      addLog(`🚫 Policy BLOCKED: ${result.reasonCodes.join(', ')}`, 'error');
    }
  };

  const handleCopyLog = () => {
    const text = logs
      .map((l) => {
        const parts = l.split('|');
        return parts.length >= 3 ? `[${parts[1]}] ${parts.slice(2).join('|')}` : l;
      })
      .join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopyLabel('Copied!');
      setTimeout(() => setCopyLabel('Copy Log'), 2000);
    });
  };

  const presentOID4VP = async (
    authRequest: AuthorizationRequest,
    scenarioId: string,
    decisionId: string | null = null
  ) => {
    let holderKeys: CryptoKeyPair | null = null;
    let issuerKeys: CryptoKeyPair | null = null;

    try {
      setStatus('PROVING');
      addLog('🔐 Generating SD-JWT Verifiable Presentation...', 'info');

      holderKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ]);
      issuerKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ]);

      const claims = SCENARIO_CLAIMS[scenarioId] || SCENARIO_CLAIMS['liquor-store'];
      const vct = SCENARIO_VCT[scenarioId] || 'https://mitch.demo/vct/age-credential';

      const { vpTokenString, presentationSubmission, disclosedClaims } =
        await buildSDJWTPresentation({
          request: authRequest,
          issuerPrivateKey: issuerKeys.privateKey,
          holderKeyPair: holderKeys,
          claims,
          vct,
          issuerDid: 'https://issuer.mitch.demo',
          revoked: scenarioId === 'revoked',
        });

      addLog(`📋 Disclosed: ${Object.keys(disclosedClaims).join(', ')}`, 'info');
      addLog(`🔑 Key Binding JWT attached (nonce + aud bound)`, 'info');

      const issuerPubJwk = await crypto.subtle.exportKey('jwk', issuerKeys.publicKey);
      const redirectUri = authRequest.redirect_uri;
      addLog(`🚀 POSTing VP to ${redirectUri}...`, 'info');

      // U-22/U-23: Apply Anti-Fingerprinting (Padding + Uniform Headers + Jitter)
      const payload = {
          vp_token: vpTokenString,
          presentation_submission: presentationSubmission,
          state: authRequest.state,
          issuer_jwk: issuerPubJwk,
      };
      const paddedPayload = padPayload(payload);
      addLog(`🛡️ OID4VP Payload padded to ${paddedPayload.length} bytes`, 'info');

      await applyJitter(20, 100);
      addLog('🛡️ Applied timing jitter', 'info');

      const response = await fetch(redirectUri, {
        method: 'POST',
        headers: UNIFORM_HEADERS,
        body: paddedPayload,
      });

      const result = (await response.json()) as {
        ok: boolean;
        disclosedClaims?: Record<string, unknown>;
        errors?: string[];
        error?: string;
      };

      if (result.ok) {
        addLog('✅ Verifier confirmed: Presentation VALID', 'success');
        if (result.disclosedClaims) {
          addLog(`👁️ Verifier sees: ${JSON.stringify(result.disclosedClaims)}`, 'info');
        }
        setFlashAllow(true);
        setTimeout(() => setFlashAllow(false), 900);
      } else {
        addLog(
          `⚠️ Verifier rejected: ${result.errors?.join(', ') ?? result.error ?? 'unknown'}`,
          'warning'
        );
      }

      const { consentReceipt, auditEntry } = buildSessionCleanup({
        request: authRequest,
        disclosedClaims,
        outcome: result.ok ? 'SUCCESS' : 'DENIED',
        decisionId,
      });
      setLastConsentReceipt(consentReceipt);
      setConsentReceiptHistory(
        appendConsentReceiptHistory({
          receipt: consentReceipt,
          outcome: result.ok ? 'SUCCESS' : 'DENIED',
          decisionId,
        })
      );
      addLog(`📝 Audit: ${auditEntry.outcome} — receipt ${consentReceipt.id}`, 'info');

      setLogs((prev) => [...prev, 'DONE|--- OID4VP PROOF COMPLETE ---']);
      setStatus('SHREDDED');
      setShowConsentManager(true);
    } catch (error) {
      addLog(
        `❌ OID4VP Proof Failed: ${error instanceof Error ? error.message : 'Unknown'}`,
        'error'
      );
      setStatus('IDLE');
    } finally {
      holderKeys = null;
      issuerKeys = null;
      addLog('🗑️ Ephemeral keys destroyed (crypto-shredding)', 'info');
    }
  };

  const handleIncomingOID4VP = async (params?: { scenario: string; endpoint: string; verifier: string }) => {
    if (!internalWalletRef.current) return;
    const data = params || incomingOID4VP;
    if (!data) return;
    const { scenario, endpoint, verifier } = data;

    // G-110: Notify verifier that we scanned the QR (robust handoff feedback)
    fetch(`${endpoint}/notify-scan`, { method: 'POST', headers: UNIFORM_HEADERS }).catch(() => {});

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
      const { authRequest } = (await authRes.json()) as { authRequest: AuthorizationRequest };

      addLog(
        `📄 Received PD: ${authRequest.presentation_definition.name ?? authRequest.presentation_definition.id}`,
        'info'
      );

      // Step 2: Policy evaluation (convert OID4VP request to VerifierRequest for policy engine)
      const policyRequest: VerifierRequest = {
        verifierId: verifier,
        requestedClaims: authRequest.presentation_definition.input_descriptors.flatMap(
          (d) => d.constraints?.fields?.flatMap((f) => f.path.map((p) => p.replace('$.', ''))) ?? []
        ),
        requestedProvenClaims: [],
        origin: endpoint,
      };
      setCurrentRequest(policyRequest);

      const context: EvaluationContext = {
        timestamp: Date.now(),
        userDID: 'did:example:wallet-user',
      };
      const result = await internalWalletRef.current.evaluateRequest(policyRequest, context);
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
        await presentOID4VP(authRequest, scenario, result.decisionCapsule?.decision_id ?? null);
        
        // G-120: If in popup, notify opener
        if (window.opener) {
          window.opener.postMessage({ type: 'MITCH_PROOF_COMPLETE', success: true }, '*');
        }
      }
    } catch (e) {
      addLog(`❌ OID4VP Error: ${(e as Error).message}`, 'error');
      setStatus('IDLE');
    }

    // Clear URL params so page refresh doesn't re-trigger
    window.history.replaceState({}, '', window.location.pathname);
  };

  const handleFetchCredential = async () => {
    setCredentialStatus('fetching');
    addLog('🎫 Fetching credential from issuer-mock (OID4VCI)...', 'info');
    try {
      const res = await fetch('http://localhost:3005/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: 'did:example:wallet-user',
          claims: {
            name: 'Demo User',
            dateOfBirth: '1990-01-01',
            age: 36,
          },
        }),
      });
      if (!res.ok) throw new Error('Issuer failed');
      addLog('✅ New SD-JWT VC received and stored securely', 'success');
      await loadWalletCredentials();
      setCredentialStatus('done');
    } catch (e) {
      addLog(`❌ OID4VCI Failed: ${(e as Error).message}`, 'error');
      setCredentialStatus('error');
    }
  };

  return (
    <div className={`wallet-container ${flashAllow ? 'flash-allow' : ''}`}>
      <header className="wallet-header">
        <div className="wallet-logo">
          mi<span>T</span>ch
        </div>
        <div className="wallet-version">v1.0-RC</div>
      </header>

      <main className="wallet-main">
        {status === 'IDLE' && guidedDemoActive && (
          <GuidedDemoMode 
            isActive={guidedDemoActive}
            onExit={() => setGuidedDemoActive(false)}
            onStepExecute={() => {}}
            steps={DEMO_STEPS_CONFIG as any}
          />
        )}

        {status === 'LOCKED_PASSKEY' && (
          <div className="secure-backdrop" style={{ display: 'flex' }}>
            <div className="secure-prompt" style={{ textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 64, marginBottom: 20 }}>🔐</div>
              <h2 style={{ fontSize: 24, marginBottom: 12 }}>Wallet Locked</h2>
              <p style={{ color: '#94a3b8', marginBottom: 32 }}>
                Use your Passkey (Fingerprint, Face ID or Windows Hello) to securely unlock your miTch Wallet.
              </p>
              <button
                onClick={handlePasskeyUnlock}
                style={{
                  width: '100%',
                  padding: '16px',
                  background: '#0891b2',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 12,
                  fontWeight: 700,
                  fontSize: 16,
                  cursor: 'pointer',
                  boxShadow: '0 4px 14px 0 rgba(8, 145, 178, 0.39)',
                }}
              >
                Unlock with Biometrics
              </button>
              <div style={{ marginTop: 24 }}>
                <button 
                  onClick={async () => {
                    const wallet = internalWalletRef.current;
                    if (!wallet) return;
                    await wallet.initialize();
                    setCurrentPolicy(wallet.getPolicy());
                    await loadWalletCredentials();
                    setStatus('IDLE');
                    addLog('🔓 Fallback: Unlocked via PIN', 'warning');
                  }}
                  style={{ background: 'none', border: 'none', color: '#64748b', fontSize: 13, textDecoration: 'underline', cursor: 'pointer' }}
                >
                  Use PIN instead
                </button>
              </div>
            </div>
          </div>
        )}

        {status !== 'LOCKED' && status !== 'LOCKED_PASSKEY' && status !== 'UNLOCKING' && (
          <>
            <div className="credential-card-list">
              {credentials.map((cred) => {
                const types = cred.type || [];
                let cardClass = '';
                let displayName = 'Identity Credential';
                let icon = '🪪';
                let subText = 'Generic eID';

                if (types.includes('AgeCredential')) {
                  cardClass = 'credential-card--age';
                  displayName = 'Government ID (Age Proof)';
                  icon = '👤';
                  subText = 'Official Identity Document';
                } else if (types.includes('EmploymentCredential')) {
                  cardClass = 'credential-card--employment';
                  displayName = 'Hospital Practitioner ID';
                  icon = '🏥';
                  subText = 'St. Mary Hospital Professional';
                } else if (types.includes('PatientSummary')) {
                  cardClass = 'credential-card--summary';
                  displayName = 'EHDS Patient Health Summary';
                  icon = '📋';
                  subText = 'Clinical Diagnostic Record';
                } else if (types.includes('Prescription')) {
                  cardClass = 'credential-card--prescription';
                  displayName = 'ePrescription Record';
                  icon = '💊';
                  subText = 'Authorized Medical Rx';
                } else if (types.includes('org.iso.18013.5.1.mDL') || cred.format === 'mso_mdoc') {
                  cardClass = 'credential-card--mdl';
                  displayName = 'Mobile Driver License (mDL)';
                  icon = '🚗';
                  subText = 'ISO 18013-5 Compliant';
                }

                return (
                  <div key={cred.id} className={`credential-card ${cardClass}`}>
                    <div className="credential-card-header">
                      <span className="credential-card-label">{subText}</span>
                      <span className="credential-trust-badge">✓ Trusted</span>
                    </div>
                    <div className="credential-card-body">
                      <div className="credential-card-icon">{icon}</div>
                      <div className="credential-card-info">
                        <div className="credential-card-name">{displayName}</div>
                        <div className="credential-card-issuer">Issuer: {cred.issuer}</div>
                      </div>
                    </div>
                    <div className="credential-card-footer">
                      <span>Ref: {cred.id.substring(0, 8)}...</span>
                      <span>Verified: {new Date(cred.issuedAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="quick-actions">
              <h3>⚡ Quick Actions</h3>
              <div className="actions-grid">
                <button
                  id="btn-liquor-store"
                  className="action-btn"
                  onClick={handleProveAge}
                  disabled={status === 'EVALUATING'}
                >
                  🍺 Age Check
                </button>
                <button
                  className="action-btn"
                  onClick={handleMultiProofDemo}
                  disabled={status === 'EVALUATING'}
                >
                  🏥 Doctor Login
                </button>
                <button
                  className="action-btn"
                  onClick={handleHealthAccessDemo}
                  disabled={status === 'EVALUATING'}
                >
                  🚑 EHDS ER
                </button>
                <button
                  className="action-btn"
                  onClick={handlePharmacyDemo}
                  disabled={status === 'EVALUATING'}
                >
                  💊 Pharmacy
                </button>
                <button
                  className="action-btn action-btn--secondary"
                  onClick={handleWebAuthnDemo}
                  disabled={status === 'EVALUATING'}
                >
                  🔐 HW Presence
                </button>
                <button
                  className="action-btn action-btn--secondary"
                  onClick={handleRecoveryTest}
                  disabled={status === 'EVALUATING'}
                >
                  🛡️ Social Recovery
                </button>
                <button
                  className="action-btn action-btn--accent"
                  onClick={handleFetchCredential}
                  disabled={credentialStatus === 'fetching'}
                >
                  🎫 Get New VC
                </button>
              </div>
            </div>
          </>
        )}
      </main>

      <aside className="wallet-sidebar">
        <div className="audit-log-container">
          <div className="audit-log-header">
            <h3>📜 Transaction Audit</h3>
            <button className="copy-btn" onClick={handleCopyLog}>
              {copyLabel}
            </button>
          </div>
          <div className="audit-log" ref={logContainerRef}>
            {logs.map((log, i) => {
              const [type, ...rest] = log.split('|');
              return (
                <div key={i} className={`log-entry log-entry--${type.toLowerCase()}`}>
                  {rest.join('|')}
                </div>
              );
            })}
            {logs.length === 0 && <div className="log-empty">No transactions yet.</div>}
          </div>
        </div>

        <div className="wallet-controls">
          <button className="control-btn" onClick={() => setShowSecondary(!showSecondary)}>
            {showSecondary ? 'Hide Details' : 'Show Wallet Stats'}
          </button>
          {showSecondary && (
            <div className="secondary-stats">
              <div className="stat-item">
                <span>Protection Layer:</span>
                <span className="stat-value stat-value--active">ACTIVE</span>
              </div>
              <div className="stat-item">
                <span>ZKP Engine:</span>
                <span className="stat-value">v2.1.0</span>
              </div>
              <div className="stat-item">
                <span>Identity Key:</span>
                <span className="stat-value stat-value--success">SECURE (SE)</span>
              </div>
            </div>
          )}
          <button className="control-btn" onClick={() => setShowDataFlow(true)}>
            📊 Data Flow Explorer
          </button>
          <button className="control-btn" onClick={() => setShowConsentManager(true)}>
            🛠️ Manual Policy
          </button>
        </div>
      </aside>

      {showConsent && evaluationResult?.decisionCapsule && (
        <ConsentModal
          capsule={evaluationResult.decisionCapsule}
          reasonCodes={evaluationResult.reasonCodes}
          timeoutMinutes={currentPolicy?.globalSettings?.requireConsentTimeoutMinutes}
          onApprove={(_presenceProof) => {
            setShowConsent(false);
            const pendingAuth = (window as unknown as Record<string, unknown>)
              ._pendingAuthRequest as AuthorizationRequest | undefined;
            const pendingScenario = (window as unknown as Record<string, unknown>)
              ._pendingScenario as string | undefined;
            if (pendingAuth && pendingScenario) {
              delete (window as unknown as Record<string, unknown>)._pendingAuthRequest;
              delete (window as unknown as Record<string, unknown>)._pendingScenario;
              presentOID4VP(
                pendingAuth,
                pendingScenario,
                evaluationResult?.decisionCapsule?.decision_id ?? null
              );
            } else {
              proceedWithProof(evaluationResult, undefined, currentRequest?.serviceEndpoint);
            }
          }}
          onReject={() => {
            setStatus('DENIED');
            addLog('🚫 User rejected via Secure UI', 'error');
            const pendingAuth = (window as unknown as Record<string, unknown>)
              ._pendingAuthRequest as AuthorizationRequest | undefined;
            if (pendingAuth) {
              delete (window as unknown as Record<string, unknown>)._pendingAuthRequest;
              delete (window as unknown as Record<string, unknown>)._pendingScenario;
            }
            setShowConsent(false);
          }}
          onLog={addLog}
        />
      )}

      {status === 'DENIED' && evaluationResult?.denialResolution && (
        <div className="secure-backdrop">
          <div
            className="secure-prompt"
            style={{
              borderTop: `4px solid ${evaluationResult.denialResolution.severity === 'CRITICAL' ? '#E53935' : '#F57C00'}`,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 15 }}>
              <div style={{ fontSize: 24 }}>
                {evaluationResult.denialResolution.severity === 'CRITICAL' ? '⛔' : '⚠️'}
              </div>
              <h2 style={{ fontSize: 20, margin: 0 }}>{evaluationResult.denialResolution.title}</h2>
            </div>

            <p style={{ color: '#ccc', fontSize: 16, lineHeight: 1.5, marginBottom: 20 }}>
              {evaluationResult.denialResolution.message}
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {evaluationResult.denialResolution.actions.map((action) => (
                <button
                  key={action.id}
                  onClick={async () => {
                    addLog(`👉 User triggered: ${action.label}`, 'info');
                    if (internalWalletRef.current) {
                        const actionResult = await (internalWalletRef.current as any).handleAction(action);
                        if (actionResult.success) {
                        addLog(`✅ Action Completed: ${actionResult.message}`, 'success');

                        if (action.type === 'OVERRIDE_WITH_CONSENT') {
                            addLog('🔄 Re-evaluating with override permission...', 'info');

                            if (!currentRequest) {
                            addLog('❌ Error: Original request lost from context.', 'error');
                            setStatus('DENIED');
                            return;
                            }

                            const overrideResult = await internalWalletRef.current.evaluateRequest(
                            currentRequest,
                            {
                                timestamp: Date.now(),
                                userDID: 'did:example:wallet-user',
                                overrideGranted: true,
                            }
                            );
                            if (overrideResult.verdict === 'PROMPT') {
                            setEvaluationResult(overrideResult);
                            setShowConsent(true);
                            } else {
                            addLog(
                                '❌ Override failed: Could not generate proof authorization',
                                'error'
                            );
                            setStatus('DENIED');
                            }
                        } else {
                            setTimeout(() => {
                            setStatus('IDLE');
                            addLog('🔄 Wallet ready for new transaction', 'info');
                            }, 1500);
                        }
                        }
                    }
                  }}
                  className={`denial-action-btn${action.type === 'OVERRIDE_WITH_CONSENT' ? ' denial-action-btn--override' : ''}`}
                >
                  {action.label}
                </button>
              ))}
              <button
                className="denial-action-btn denial-action-btn--secondary"
                onClick={() => setStatus('IDLE')}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {showDataFlow && (
        <div className="secure-backdrop">
          <DataFlowPanel
            entries={recentAuditEntries}
            onAction={() => setShowDataFlow(false)}
          />
        </div>
      )}

      {showConsentManager && (
        <div className="secure-backdrop">
          <div className="secure-prompt" style={{ maxWidth: '90vw', height: '80vh', overflowY: 'auto', padding: 0 }}>
             <button 
                onClick={() => setShowConsentManager(false)}
                style={{ position: 'absolute', top: 16, right: 16, zIndex: 10, background: 'rgba(0,0,0,0.5)', border: 'none', color: '#fff', borderRadius: '50%', width: 32, height: 32, cursor: 'pointer' }}
             >✕</button>
             <ConsentManagerPanel
                request={currentRequest}
                result={evaluationResult}
                auditEntries={recentAuditEntries}
                privacyConsent={null}
                consentReceipt={lastConsentReceipt}
                receiptHistory={consentReceiptHistory}
                onOpenDataFlow={() => { setShowConsentManager(false); setShowDataFlow(true); }}
             />
          </div>
        </div>
      )}

      {showPopupBlocked && (
        <PopupBlockedModal 
          url={blockedPopupUrl} 
          onClose={() => setShowPopupBlocked(false)} 
        />
      )}

      {status === 'EVALUATING' && (
        <div className="secure-backdrop">
          <div className="secure-prompt">
            <div className="spinner"></div>
            <p>miTch is evaluating verifier risk...</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const showWalletDemo =
    import.meta.env.MODE === 'test' ||
    new URLSearchParams(window.location.search).get('demo') === 'wallet';

  if (showWalletDemo) {
    return <WalletApp />;
  }

  return (
    <LandingPage
      onLaunchDemo={() => {
        window.location.href = `${window.location.pathname}?demo=wallet`;
      }}
    />
  );
}
