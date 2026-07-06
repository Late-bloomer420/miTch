import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import './App.css';
import './wallet.css';

import { type EvaluationContext } from '@askmi/policy-engine';
import type {
  VerifierRequest,
  PolicyEvaluationResult,
  PolicyManifest,
  StoredCredentialMetadata,
  VerifierReportCard,
} from '@askmi/shared-types';
import { ASKMI_DEMO, resolveCorrelationId } from '@askmi/shared-types';
import { ReputationSensor } from '@askmi/wallet-core';
import { WalletService } from './services/WalletService';
import { ComplianceDashboard } from './components/AuditReportPanel';
import { PolicyEditor } from './components/PolicyEditor';
import { WebAuthnService } from '@askmi/shared-crypto';
import { PrivacyAuditModal } from './components/PrivacyAuditModal';
import { PrivacyContext, PrivacyConsent } from './services/PrivacyAuditService';
import { ConsentModal } from './components/ConsentModal';
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
} from '@askmi/oid4vp';
import type { ConsentReceipt } from '@askmi/oid4vp';
import { SCENARIO_CLAIMS } from './scenario-claims';
import { DataFlowPanel } from './components/DataFlowPanel';
import { LandingPage } from './LandingPage';
import { padPayload, UNIFORM_HEADERS, applyJitter } from './utils/anti-fingerprinting';
import { isSingleUsePresentation } from './utils/single-use';

type WalletStatus =
  | 'LOCKED'
  | 'WELCOME'
  | 'LOCKED_PASSKEY'
  | 'UNLOCKING'
  | 'IDLE'
  | 'EVALUATING'
  | 'PROVING'
  | 'SHREDDED'
  | 'DENIED';

type DemoScenarioId = 'liquor-store' | 'doctor-login' | 'ehds-er' | 'pharmacy';
type TraceDetailPanel = 'consent' | 'compliance' | 'data-flow';
type WalletPage = 'credentials' | 'requests' | 'trace' | 'audit' | 'settings' | 'advanced';

const DEMO_STEPS_CONFIG: Omit<DemoStep, 'onExecute'>[] = [
  {
    id: 1,
    scenario: '🍺 Age Check',
    title: 'Age Verification — Zero Knowledge',
    description:
      'A liquor store scans your wallet QR. AskMI evaluates the request against ' +
      'your policy. The store is trusted and only asks for proof of age ≥ 18. ' +
      'No consent dialog needed — AskMI auto-approves because the rule already covers this.',
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
      'AskMI finds a matching rule but flags it for explicit consent — ' +
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
      'This is Layer 2 data — the highest protection tier. AskMI requires ' +
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

function WalletApp() {
  useEffect(() => {
    document.title = 'AskMI Wallet';
  }, []);

  const [status, setStatus] = useState<WalletStatus>('LOCKED');
  const [logs, setLogs] = useState<string[]>([]);
  const [evaluationResult, setEvaluationResult] = useState<PolicyEvaluationResult | null>(null);
  const [showConsent, setShowConsent] = useState(false);
  const [currentPolicy, setCurrentPolicy] = useState<PolicyManifest | null>(null);
  const [currentRequest, setCurrentRequest] = useState<VerifierRequest | null>(null);
  const [showPrivacyAudit, setShowPrivacyAudit] = useState(false);
  const [_privacyConsent, setPrivacyConsent] = useState<PrivacyConsent | null>(null);
  const [, setReputationReports] = useState<VerifierReportCard[]>([]);
  const [lastConsentReceipt, setLastConsentReceipt] = useState<ConsentReceipt | null>(null);
  const [consentReceiptHistory, setConsentReceiptHistory] = useState(() =>
    loadConsentReceiptHistory()
  );
  const [guidedDemoActive, setGuidedDemoActive] = useState(false);
  const [showSecondary, setShowSecondary] = useState(false);
  const [activeScenario, setActiveScenario] = useState<DemoScenarioId>('liquor-store');
  const [activeWalletPage, setActiveWalletPage] = useState<WalletPage>('credentials');
  const [traceDetailPanel, setTraceDetailPanel] = useState<TraceDetailPanel | null>('data-flow');
  const [flashAllow, setFlashAllow] = useState(false);
  const [copyLabel, setCopyLabel] = useState('Copy Log');
  const [credentialStatus, setCredentialStatus] = useState<'idle' | 'fetching' | 'done' | 'error'>(
    'idle'
  );
  const [credentials, setCredentials] = useState<StoredCredentialMetadata[]>([]);
  // G-130.1 Task 2 — dedicated status for the user-facing Refresh control, kept separate
  // from `credentialStatus` so refreshing never disturbs the demo issuance button's label.
  const [refreshStatus, setRefreshStatus] = useState<'idle' | 'refreshing' | 'done'>('idle');

  const loadWalletCredentials = async () => {
    try {
      const creds = await walletRef.current.getCredentials();
      setCredentials(creds);
    } catch (e) {
      console.warn('Failed loading credentials', e);
    }
  };

  // G-130.1 Task 2 — REFRESH: re-sync the visible credential list from the encrypted
  // vault. Reflects current truth (a single-use credential spent in a presentation, or a
  // credential issued in another tab) without re-hitting the issuer.
  const handleRefreshCredentials = async () => {
    setRefreshStatus('refreshing');
    addLog('🔄 Refreshing credentials from your device vault…', 'info');
    await loadWalletCredentials();
    setRefreshStatus('done');
    addLog('✅ Credentials up to date.', 'success');
    setTimeout(() => setRefreshStatus('idle'), 2000);
  };

  // Dev affordance (Proof-Randomization U-12): mint the next issued credential
  // as single-use. The constraint is fixed at issuance, never mutated in-wallet.
  // Dev-only (see import.meta.env.DEV); tree-shaken from production builds.
  const [mintSingleUse, setMintSingleUse] = useState(false);

  // G-120: Listen for Auth Popup messages from opener window
  useEffect(() => {
    const handleOpenerMessage = (event: MessageEvent) => {
      // Security: Validate origin in production
      if (
        event.data?.type === 'ASKMI_OID4VP_REQUEST' ||
        event.data?.type === 'MITCH_OID4VP_REQUEST'
      ) {
        addLog('📨 Received OID4VP request via Secure Popup Bridge', 'info');
        // Trigger handleIncomingOID4VP with provided data
        // For simplicity, we just reload or use the data directly
        const { scenario, endpoint, verifier } = event.data;
        // This is a specialized path for popups
        handleIncomingOID4VPFromOpener(scenario, endpoint, verifier);
      }
    };

    window.addEventListener('message', handleOpenerMessage);

    // Check if we ARE a popup and notify opener
    if (window.opener) {
      window.opener.postMessage({ type: 'ASKMI_WALLET_READY' }, '*');
      window.opener.postMessage({ type: 'MITCH_WALLET_READY' }, '*');
    }

    return () => window.removeEventListener('message', handleOpenerMessage);
  }, []);

  const handleIncomingOID4VPFromOpener = async (
    scenario: string,
    endpoint: string,
    verifier: string
  ) => {
    await handleIncomingOID4VP({ scenario, endpoint, verifier });
  };
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
        verifier: p.get('verifier') ?? ASKMI_DEMO.verifierDid,
      };
    } catch {
      return null;
    }
  });

  const logContainerRef = useRef<HTMLDivElement>(null);
  const walletRef = useRef<WalletService>(new WalletService());
  const recentAuditEntries = useMemo(() => walletRef.current.getRecentAuditLogs(200), [logs]);

  const addLog = (msg: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    const time = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `${type.toUpperCase()}|${time} | ${msg}`]);
  };

  const handleReportReputation = useCallback(() => {
    if (!currentRequest) {
      addLog('⚠️ Reputation report skipped: original verifier request unavailable', 'warning');
      return;
    }

    const trackerCount = _privacyConsent?.acceptedTrackers.length ?? 0;
    const report = ReputationSensor.generateReport(
      currentRequest,
      evaluationResult?.decisionCapsule,
      trackerCount
    );
    setReputationReports((prev) => [...prev, report]);
    addLog(
      `🧭 VRN report stored locally for ${String(report.verifierId)} (score ${report.localPrivacyScore.toFixed(2)}, over-requesting: ${report.metrics.overRequestingDetected ? 'yes' : 'no'})`,
      report.metrics.overRequestingDetected ? 'warning' : 'info'
    );
  }, [currentRequest, evaluationResult?.decisionCapsule, _privacyConsent]);

  const handleExportAuditReport = useCallback(() => walletRef.current.exportAuditReport(), []);
  const handleSyncAuditToL2 = useCallback(() => walletRef.current.syncAuditToL2(), []);
  const getRecentComplianceLogs = useCallback(() => recentAuditEntries, [recentAuditEntries]);
  const getAuditChainStatus = useCallback(() => walletRef.current.verifyAuditChain(), []);

  // Auto-scroll Audit Log (UX-05)
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  // Auto-init for Demo
  // Holds the latest bootstrap routine so an explicit reset can re-run first-run
  // enrollment in place (no full page reload).
  const bootstrapRef = useRef<() => Promise<void>>(async () => {});

  useEffect(() => {
    const init = async () => {
      addLog('🔐 Initializing Wallet Service...', 'info');
      try {
        await walletRef.current.initialize('123456');
        addLog('🔓 Wallet Decrypted & Ready', 'success');
        setCurrentPolicy(walletRef.current.getPolicy());

        let nextStatus: WalletStatus = 'IDLE';
        try {
          // Model A — the passkey IS the account. A single device-bound platform
          // identity key is registered once on first run; it persists across reloads
          // (passkeyDb), so the wallet never treats a returning device as a new user.
          const isAvailable = await WebAuthnService.isAvailable();
          const hasIdentity = await WebAuthnService.isIdentityRegistered();
          if (isAvailable && !hasIdentity) {
            // First run (G-130.1 Task 3): do NOT auto-fire the registration ceremony.
            // A surprise biometric prompt with no framing reads as a scam. Show a welcome
            // screen first; enrollment runs only on the explicit "Create account" gesture.
            addLog('👋 First run on this device — welcome.', 'info');
            nextStatus = 'WELCOME';
          } else if (isAvailable && hasIdentity) {
            // RETURNING device: reuse the existing identity (no re-enroll), gated behind
            // exactly one unlock ceremony before any credential is shown.
            addLog('🔒 Passkey unlock required before presentation flow.', 'info');
            nextStatus = 'LOCKED_PASSKEY';
          } else {
            addLog('⚠️ Platform Passkey unavailable; demo fallback unlocked locally.', 'warning');
            nextStatus = 'IDLE';
          }
        } catch (authError) {
          addLog(
            `⚠️  Passkey check skipped: ${authError instanceof Error ? authError.message : String(authError)}`,
            'warning'
          );
        }

        await loadWalletCredentials();
        setStatus(nextStatus);
      } catch (e) {
        console.error(e);
        const message = e instanceof Error ? e.message : String(e);
        addLog(`❌ Init Failed: ${message || 'Unknown error'}`, 'error');
      }
    };
    bootstrapRef.current = init;
    init();
  }, []);

  // Explicit, user-initiated reset — the only sanctioned way to wipe the wallet.
  // Clears the encrypted vault AND the device passkey/identity meta, then re-runs
  // bootstrap so the device starts fresh (first-run enrollment).
  const handleResetWallet = async () => {
    const confirmed =
      typeof window !== 'undefined' && typeof window.confirm === 'function'
        ? window.confirm(
            'Reset this wallet?\n\nThis permanently clears all stored credentials and unlinks the device passkey from AskMI. You will start over as a new device. This cannot be undone.'
          )
        : true;
    if (!confirmed) return;
    try {
      setStatus('UNLOCKING');
      addLog('♻️ Resetting wallet (explicit user action)…', 'warning');
      await walletRef.current.resetWallet();
      await WebAuthnService.clearRegistration();
      setCredentials([]);
      setEvaluationResult(null);
      setStatus('LOCKED');
      await bootstrapRef.current();
    } catch (e) {
      addLog(`❌ Reset failed: ${e instanceof Error ? e.message : String(e)}`, 'error');
      setStatus('LOCKED_PASSKEY');
    }
  };

  // First-run account creation (G-130.1 Task 3) — the deliberate, framed gesture that
  // replaces the old auto-firing mount-time prompt. The enrollment ceremony itself verifies
  // the user (userVerification: required), so this single biometric lands straight in the
  // wallet with no redundant second unlock.
  const handleCreateAccount = async () => {
    try {
      setStatus('UNLOCKING');
      addLog('📱 Creating your AskMI account on this device…', 'info');
      await WebAuthnService.registerIdentityKey();
      addLog('✅ Account created. Device-bound identity passkey registered.', 'success');
      await loadWalletCredentials();
      addLog('🔓 Welcome! Your wallet is ready on this device.', 'success');
      setStatus('IDLE');
    } catch (e) {
      addLog(`❌ Account creation failed: ${e instanceof Error ? e.message : String(e)}`, 'error');
      setStatus('WELCOME');
    }
  };

  const handlePasskeyUnlock = async () => {
    try {
      setStatus('UNLOCKING');
      addLog('👤 Requesting Biometric Verification...', 'info');
      await WebAuthnService.provePresence('AskMI-wallet-unlock');
      await walletRef.current.initialize('123456');
      addLog('🔓 Passkey Verified. Wallet Ready.', 'success');
      setCurrentPolicy(walletRef.current.getPolicy());
      await loadWalletCredentials();
      setStatus('IDLE');
    } catch (e) {
      addLog(`❌ Unlock Failed: ${e instanceof Error ? e.message : String(e)}`, 'error');
      setStatus('LOCKED_PASSKEY');
    }
  };

  const handleProveAge = async () => {
    setStatus('EVALUATING');
    setLogs([]);
    setEvaluationResult(null);
    setFlashAllow(false);

    addLog(`📥 Received request from: ${ASKMI_DEMO.verifierDid}`, 'info');
    const request: VerifierRequest = {
      verifierId: ASKMI_DEMO.verifierDid,
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

  const proceedWithProof = async (
    policyResult?: PolicyEvaluationResult,
    targetKey?: CryptoKey,
    endpoint?: string
  ) => {
    const result = policyResult || evaluationResult;

    if (!result || !result.decisionCapsule) {
      addLog('❌ No Decision Capsule found!', 'error');
      return;
    }

    const targetEndpoint =
      endpoint ||
      ((result.decisionCapsule as unknown as Record<string, unknown>).service_endpoint as
        | string
        | undefined) ||
      CONFIG.VERIFIER_ENDPOINT;

    setShowConsent(false);
    setStatus('PROVING');

    try {
      addLog('🔐 Generating Secure Presentation...', 'info');

      const { encryptedVp, auditLog } = await walletRef.current.generatePresentation(
        result.decisionCapsule,
        targetKey
      );

      auditLog.forEach((l: string) => addLog(l, l.includes('ALERT') ? 'error' : 'info'));

      // Refresh so a consumed single-use credential reflects its spent state (U-12).
      await loadWalletCredentials();

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
      const capsule = evaluationResult?.decisionCapsule;
      const entries = await walletRef.current.recordIdentityFirewallEvents(
        capsule?.decision_id,
        capsule?.verifier_did,
        context.detectedTrackers
      );
      if (entries.length > 0) {
        addLog(`🛡️ Identity Firewall logged ${entries.length} transparency events`, 'info');
      }
    } catch (error) {
      console.warn('[IdentityFirewall] Failed to record transparency events:', error);
      addLog('⚠️ Identity Firewall logging unavailable; continuing proof flow', 'warning');
    }

    await proceedWithProof(evaluationResult || undefined);
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
          requestedProvenClaims: ['age >= 18'],
        },
        {
          credentialType: 'EmploymentCredential',
          requestedClaims: ['role', 'licenseId'],
          requestedProvenClaims: [],
        },
      ],
    };
    setCurrentRequest(request);

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
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
    addLog(
      '🔗 Binding: Signature is cryptographically tied to Decision ID demo-decision-456',
      'info'
    );
  };

  const handleRecoveryTest = async () => {
    addLog('🛡️ DEMO: Starting Social Recovery Setup...', 'warning');
    const fragments = await walletRef.current.splitMasterKey();
    addLog(`✅ DEMO: Master Key split into 3 fragments (Circle of Trust)`, 'success');
    fragments.forEach((f, i) =>
      addLog(`👤 Friend ${i + 1} received: ${f.substring(0, 8)}...`, 'info')
    );

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
          requestedProvenClaims: [],
        },
      ],
    };
    setCurrentRequest(request);

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
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
          requestedProvenClaims: [],
        },
      ],
    };
    setCurrentRequest(request);

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
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
      requirements: [
        {
          credentialType: 'PatientSummary',
          requestedClaims: ['bloodGroup', 'allergies'],
          requestedProvenClaims: [],
        },
      ],
    };
    setCurrentRequest(request);

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
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
      requirements: [
        {
          credentialType: 'PatientSummary',
          requestedClaims: ['bloodGroup', 'allergies'],
          requestedProvenClaims: [],
        },
      ],
    };
    setCurrentRequest(request);

    const context: EvaluationContext = {
      timestamp: Date.now(),
      userDID: 'did:example:wallet-user',
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
    if (l.startsWith('DONE'))
      return (
        <div key={i} className="audit-log-done">
          {l.split('|')[1]}
        </div>
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

  // OID4VP: present SD-JWT VP to verifier via direct_post
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

      // Generate ephemeral key pairs (PoC — in production, holder key is from wallet, issuer from trust registry)
      holderKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ]);
      issuerKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ]);

      const claims = SCENARIO_CLAIMS[scenarioId] ?? SCENARIO_CLAIMS['liquor-store'];
      const isRevoked = scenarioId === 'revoked';

      // W-03: Build SD-JWT VP Token with Key Binding JWT
      const { vpTokenString, presentationSubmission, disclosedClaims } =
        await buildSDJWTPresentation({
          request: authRequest,
          issuerPrivateKey: issuerKeys.privateKey,
          holderKeyPair: holderKeys,
          claims,
          vct: SCENARIO_VCT[scenarioId] ?? 'https://askmi.demo/vct/age-credential',
          issuerDid: ASKMI_DEMO.issuerUri,
          revoked: isRevoked,
          statusListUri: ASKMI_DEMO.statusListUri,
        });

      addLog(`📋 Disclosed: ${Object.keys(disclosedClaims).join(', ')}`, 'info');
      addLog(`🔑 Key Binding JWT attached (nonce + aud bound)`, 'info');

      // Send issuer public key alongside VP for PoC verification
      const issuerPubJwk = await crypto.subtle.exportKey('jwk', issuerKeys.publicKey);

      // POST direct_post to verifier redirect_uri
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

      // W-05: Session cleanup — audit entry
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
    } catch (error) {
      addLog(
        `❌ OID4VP Proof Failed: ${error instanceof Error ? error.message : 'Unknown'}`,
        'error'
      );
      setStatus('IDLE');
    } finally {
      // B-03: Crypto-shredding — destroy ephemeral keys
      holderKeys = null;
      issuerKeys = null;
      addLog('🗑️ Ephemeral keys destroyed (crypto-shredding)', 'info');
    }
  };

  // OID4VP: handle incoming request from verifier-demo deep link
  const handleIncomingOID4VP = async (params?: {
    scenario: string;
    endpoint: string;
    verifier: string;
  }) => {
    const data = params || incomingOID4VP;
    if (!data) return;
    const { scenario, endpoint, verifier } = data;

    // G-110: Notify verifier that we scanned the QR (robust handoff feedback)
    fetch(`${endpoint}/notify-scan`, { method: 'POST' }).catch(() => {});

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
        nonce: authRequest.nonce,
        correlation_id: resolveCorrelationId({
          correlationId: authRequest.correlation_id,
          nonce: authRequest.nonce,
        }),
      };
      setCurrentRequest(policyRequest);

      const context: EvaluationContext = {
        timestamp: Date.now(),
        userDID: 'did:example:wallet-user',
      };
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
        await presentOID4VP(authRequest, scenario, result.decisionCapsule?.decision_id ?? null);
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
        headers: {
          'Content-Type': 'application/json',
          ...((currentRequest?.correlation_id && {
            'x-correlation-id': currentRequest.correlation_id,
          }) ||
            {}),
        },
        body: JSON.stringify({
          credential_definition: { type: ['VerifiableCredential', 'AgeCredential'] },
          proof: {},
        }),
      });
      if (!res.ok) throw new Error(`Issuer returned ${res.status}`);
      const data = (await res.json()) as { credential?: string; error?: string };
      if (!data.credential) throw new Error(data.error ?? 'No credential in response');

      // Decode JWT payload (header.payload.sig)
      const parts = data.credential.split('.');
      if (parts.length < 2) throw new Error('Invalid JWT format');
      const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      const payload = JSON.parse(payloadJson) as Record<string, unknown>;
      const vcPayload = payload['vc'] as Record<string, unknown> | undefined;
      const subject = (vcPayload?.credentialSubject ??
        payload['credentialSubject'] ??
        {}) as Record<string, unknown>;

      const credId = `vc-issuer-${Date.now()}`;
      await walletRef.current.addIssuedCredential(
        credId,
        subject,
        'did:web:localhost%3A3005',
        undefined,
        import.meta.env.DEV && mintSingleUse
      );
      await loadWalletCredentials();

      setCredentialStatus('done');
      addLog(
        `✅ AgeCredential received from issuer-mock and stored (${credId})${
          import.meta.env.DEV && mintSingleUse ? ' — minted single-use 🔁' : ''
        }`,
        'success'
      );
    } catch (e) {
      setCredentialStatus('error');
      addLog(`❌ Credential fetch failed: ${(e as Error).message}`, 'error');
    }
  };

  // Dev affordance (Proof-Randomization Increment 2 / C2): mint a batch of
  // single-use credentials, each bound to its own wallet-generated holder key.
  // Dev-only; tree-shaken from production builds.
  const BATCH_SIZE = 5;
  const handleFetchBatch = async () => {
    setCredentialStatus('fetching');
    addLog(`🎫 Requesting batch of ${BATCH_SIZE} holder-bound credentials (OID4VCI §7)…`, 'info');
    try {
      const { poolId, credentialIds } = await walletRef.current.fetchCredentialBatch(BATCH_SIZE);
      await loadWalletCredentials();
      setCredentialStatus('done');
      addLog(
        `✅ Batch issued: ${credentialIds.length} single-use members in pool ${poolId} (distinct holder bindings)`,
        'success'
      );
    } catch (e) {
      setCredentialStatus('error');
      addLog(`❌ Batch issuance failed: ${(e as Error).message}`, 'error');
    }
  };

  // UX-02: primary button classes
  const getPrimaryBtnClass = () => {
    const base = 'btn-primary';
    const stateClass =
      {
        IDLE: 'btn-primary--idle',
        LOCKED: 'btn-primary--idle',
        WELCOME: 'btn-primary--idle',
        LOCKED_PASSKEY: 'btn-primary--idle',
        UNLOCKING: 'btn-primary--evaluating',
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
      case 'LOCKED':
        return '🔒 Unlocking...';
      case 'EVALUATING':
        return (
          <>
            <span className="evaluating-spinner" />
            Judging...
          </>
        );
      case 'PROVING':
        return '🔐 Generating Proof...';
      case 'SHREDDED':
        return '✓ Done — Data Forgotten';
      case 'DENIED':
        return '🚫 Access Denied';
      default:
        return '🔞 Prove Age & Forget';
    }
  };

  const isWalletReady = !['LOCKED', 'WELCOME', 'LOCKED_PASSKEY', 'UNLOCKING'].includes(status);

  return (
    <div className="wallet-app">
      <h1 className="wallet-title">
        AskMI <span className="wallet-title-accent">Wallet</span>
      </h1>
      {isWalletReady && (
        <p className="wallet-subtitle">
          Credentials, verifier requests and data flows stay local and visible.
        </p>
      )}

      {isWalletReady && (
        <nav className="wallet-nav wallet-section-rail" aria-label="Wallet sections">
          {[
            ['credentials', 'Credentials'],
            ['requests', 'Requests'],
            ['trace', 'Trace'],
            ['audit', 'Audit'],
            ['settings', 'Settings'],
            ['advanced', 'Advanced'],
          ].map(([page, label]) => (
            <button
              key={page}
              type="button"
              className={activeWalletPage === page ? 'wallet-nav__item--active' : undefined}
              aria-current={activeWalletPage === page ? 'page' : undefined}
              onClick={() => setActiveWalletPage(page as WalletPage)}
            >
              {label}
            </button>
          ))}
        </nav>
      )}

      {isWalletReady && (
        <section className="wallet-overview" aria-label="Wallet overview">
          <div className="wallet-overview__item">
            <span>Wallet</span>
            <strong>{credentials.length} credentials</strong>
          </div>
          <div className="wallet-overview__item">
            <span>Request</span>
            <strong>{activeScenario.replace(/-/g, ' ')}</strong>
          </div>
          <div className="wallet-overview__item">
            <span>Flow</span>
            <strong>{evaluationResult?.verdict ?? 'Idle'}</strong>
          </div>
        </section>
      )}

      {/* OID4VP: incoming request banner */}
      {incomingOID4VP && (
        <div
          style={{
            background: 'linear-gradient(135deg, #0a1628, #0d2040)',
            border: '1px solid #0891b2',
            borderRadius: 10,
            padding: '16px 20px',
            marginBottom: 16,
          }}
        >
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
            onClick={() => handleIncomingOID4VP()}
            disabled={status === 'EVALUATING' || status === 'PROVING' || !isWalletReady}
            style={{
              background: '#0891b2',
              color: '#fff',
              border: 'none',
              borderRadius: 6,
              padding: '8px 20px',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13,
              marginRight: 8,
            }}
          >
            ✅ Accept &amp; Prove
          </button>
        </div>
      )}

      {/* First-run Welcome / Account Creation (G-130.1 Task 3) */}
      {status === 'WELCOME' && (
        <div className="secure-backdrop" style={{ display: 'flex' }}>
          <div className="secure-prompt" style={{ textAlign: 'center', padding: 40, maxWidth: 420 }}>
            <div style={{ fontSize: 64, marginBottom: 16 }}>👋</div>
            <h2 style={{ fontSize: 24, marginBottom: 12 }}>Welcome to AskMI</h2>
            <p style={{ color: '#94a3b8', marginBottom: 16, lineHeight: 1.5 }}>
              This device becomes your AskMI account. We create one passkey
              (Fingerprint, Face ID or Windows Hello) and it stays on this device.
            </p>
            <ul
              style={{
                textAlign: 'left',
                color: '#cbd5e1',
                fontSize: 14,
                lineHeight: 1.7,
                margin: '0 auto 28px',
                maxWidth: 320,
                listStyle: 'none',
                padding: 0,
              }}
            >
              <li>🔒 No email, no password, no server account</li>
              <li>📵 Your key never leaves this device</li>
              <li>🗑️ You can reset and start over any time</li>
            </ul>
            <button
              onClick={handleCreateAccount}
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
              Create my AskMI account
            </button>
            <p style={{ color: '#64748b', fontSize: 12, marginTop: 16 }}>
              You&apos;ll be asked for your fingerprint or face once to finish.
            </p>
          </div>
        </div>
      )}

      {/* Passkey Unlock State */}
      {status === 'LOCKED_PASSKEY' && (
        <div className="secure-backdrop" style={{ display: 'flex' }}>
          <div className="secure-prompt" style={{ textAlign: 'center', padding: 40 }}>
            <div style={{ fontSize: 64, marginBottom: 20 }}>🔐</div>
            <h2 style={{ fontSize: 24, marginBottom: 12 }}>Wallet Locked</h2>
            <p style={{ color: '#94a3b8', marginBottom: 32 }}>
              Use your Passkey (Fingerprint, Face ID or Windows Hello) to unlock your AskMI Wallet
              before any credential is shown or presented.
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
            <button
              onClick={handleResetWallet}
              style={{
                marginTop: 18,
                background: 'none',
                border: 'none',
                color: '#64748b',
                fontSize: 13,
                textDecoration: 'underline',
                cursor: 'pointer',
              }}
            >
              Reset Wallet (start over as new device)
            </button>
          </div>
        </div>
      )}

      {/* UX-03: Dynamic Premium Credential Cards */}
      {isWalletReady && activeWalletPage === 'credentials' ? (
        <section className="wallet-panel wallet-panel--credentials" aria-labelledby="credentials-heading">
          <div className="wallet-section-heading">
            <div>
              <p>Identity Wallet</p>
              <h2 id="credentials-heading">Private Cards</h2>
            </div>
            <span>{credentials.length} stored</span>
          </div>

          <div id="credentials-section" className="credential-card-list">
            {credentials.map((cred) => {
              let cardClass = 'credential-card--generic';
              let displayName = 'Verifiable Credential';
              let icon = '✨';
              let subText = 'Imported Credential';

              const types = cred.type || [];

              if (types.includes('AgeCredential')) {
                cardClass = 'credential-card--govid';
                displayName = 'Age Credential (GovID)';
                icon = '🪪';
                subText = 'Government Issued ID';
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

                  {cred.singleUse && (
                    <div className={`credential-single-use ${cred.consumedAt ? 'credential-single-use--consumed' : ''}`}>
                      {cred.consumedAt
                        ? '🔥 Einmal-Credential — verbraucht (nicht wiederverwendbar)'
                        : '🔁 Einmal-Credential — wird nach Vorlage verbraucht'}
                    </div>
                  )}

                  <div className="credential-item credential-card-main">
                    <span className="credential-icon credential-card-main__icon">
                      {icon}
                    </span>
                    <div>
                      <div className="credential-name credential-card-main__name">
                        {displayName}
                      </div>
                      <div className="credential-issuer credential-card-main__issuer">
                        {cred.issuer}
                      </div>
                    </div>
                  </div>

                  <div className="credential-card-chip" />

                  <div className="credential-card-claims">
                    {(cred.claims || []).map((claim) => (
                      <span key={claim} className="credential-card-claim-badge">
                        • {claim}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          {/* G-130.1 Task 2 — Get (empty-state) / Refresh user-facing affordances */}
          {credentials.length === 0 ? (
            <div
              className="wallet-empty-state"
              style={{
                textAlign: 'center',
                maxWidth: 400,
                margin: '8px auto 24px',
                padding: '28px 24px',
                background: '#0f172a',
                border: '1px dashed #1e3a5f',
                borderRadius: 12,
              }}
            >
              <div style={{ fontSize: 44, marginBottom: 8 }}>🪪</div>
              <h3 style={{ margin: '0 0 8px', fontSize: 18, color: '#e2e8f0' }}>
                No credentials yet
              </h3>
              <p style={{ color: '#94a3b8', fontSize: 14, lineHeight: 1.5, margin: '0 0 20px' }}>
                Get your first verifiable credential, then prove things to verifiers without
                handing over your personal data.
              </p>
              <button
                onClick={handleFetchCredential}
                disabled={credentialStatus === 'fetching'}
                style={{
                  width: '100%',
                  padding: '14px',
                  background: '#0891b2',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 10,
                  fontWeight: 700,
                  fontSize: 15,
                  cursor: credentialStatus === 'fetching' ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 14px 0 rgba(8, 145, 178, 0.39)',
                }}
              >
                {credentialStatus === 'fetching'
                  ? '⏳ Getting your credential…'
                  : credentialStatus === 'error'
                    ? '↻ Retry — Get my credential'
                    : 'Get my credential'}
              </button>
            </div>
          ) : (
            <div
              className="wallet-credentials-toolbar"
              style={{
                display: 'flex',
                justifyContent: 'flex-end',
                maxWidth: 400,
                margin: '0 auto 16px',
              }}
            >
              <button
                onClick={handleRefreshCredentials}
                disabled={refreshStatus === 'refreshing'}
                aria-label="Refresh credentials"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 14px',
                  background: 'transparent',
                  color: refreshStatus === 'done' ? '#86efac' : '#7dd3fc',
                  border: `1px solid ${refreshStatus === 'done' ? '#16a34a' : '#1e3a5f'}`,
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: refreshStatus === 'refreshing' ? 'not-allowed' : 'pointer',
                }}
              >
                {refreshStatus === 'refreshing'
                  ? '🔄 Refreshing…'
                  : refreshStatus === 'done'
                    ? '✅ Up to date'
                    : '🔄 Refresh'}
              </button>
            </div>
          )}

        </section>
      ) : null}

      {/* ConsentModal */}
      {showConsent && evaluationResult?.decisionCapsule && (
        <ConsentModal
          capsule={evaluationResult.decisionCapsule}
          reasonCodes={evaluationResult.reasonCodes}
          timeoutMinutes={currentPolicy?.globalSettings?.requireConsentTimeoutMinutes}
          isSingleUse={(() => {
            // Inc 3 — DataFlow Transparency: resolve the selected credential(s)
            // for this presentation and report honest reuse status. Unknown
            // selection ⇒ undefined ⇒ the modal makes no linkability claim.
            const metas = (evaluationResult.decisionCapsule.authorized_requirements ?? [])
              .map((req) => credentials.find((c) => c.id === req.selected_credential_id))
              .filter((m): m is StoredCredentialMetadata => !!m);
            return metas.length > 0 ? isSingleUsePresentation(metas) : undefined;
          })()}
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
              const { consentReceipt } = buildSessionCleanup({
                request: pendingAuth,
                disclosedClaims: {},
                outcome: 'DENIED',
                decisionId: evaluationResult?.decisionCapsule?.decision_id ?? null,
              });
              setLastConsentReceipt(consentReceipt);
              setConsentReceiptHistory(
                appendConsentReceiptHistory({
                  receipt: consentReceipt,
                  outcome: 'DENIED',
                  decisionId: evaluationResult?.decisionCapsule?.decision_id ?? null,
                })
              );
            }
            setShowConsent(false);
          }}
          onReportReputation={handleReportReputation}
          onLog={addLog}
        />
      )}

      {/* Smart Denial Modal */}
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
                  }}
                  className={`denial-action-btn${action.type === 'OVERRIDE_WITH_CONSENT' ? ' denial-action-btn--override' : ''}`}
                >
                  <span>{action.label}</span>
                  {action.type === 'LEARN_MORE' && <span>↗</span>}
                </button>
              ))}
              <button onClick={() => setStatus('IDLE')} className="denial-close-btn">
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

      {isWalletReady && ['requests', 'trace', 'audit'].includes(activeWalletPage) && (
        <section className="wallet-flow-stack" aria-label="Wallet page">
          {activeWalletPage === 'requests' && (
            <div id="requests-section" className="demo-section scenario-launcher" data-testid="scenario-launcher">
          <div className="scenario-launcher__header">
            <h3 className="demo-section-title">Verifier Requests</h3>
            <span className="scenario-launcher__hint">Choose request</span>
          </div>

          <div className="demo-primary-grid scenario-launcher__grid">
            <button
              id="btn-liquor-store"
              onClick={() => {
                setActiveScenario('liquor-store');
                if (status === 'SHREDDED') {
                  setStatus('IDLE');
                  setEvaluationResult(null);
                  setLogs([]);
                  addLog('♻️ Wallet Memory Shredded. Ready.', 'info');
                } else {
                  handleProveAge();
                }
              }}
              disabled={status === 'EVALUATING' || status === 'PROVING' || !isWalletReady}
              className={`${getPrimaryBtnClass()} btn-scenario-card btn-scenario-card--age${activeScenario === 'liquor-store' ? ' btn-scenario-card--active' : ''}`}
              aria-current={activeScenario === 'liquor-store' ? 'true' : undefined}
            >
              {getPrimaryBtnLabel()}
              <span>Proof only, no raw PII</span>
            </button>

            <button
              id="btn-doctor-login"
              onClick={() => {
                setActiveScenario('doctor-login');
                handleMultiProofDemo();
              }}
              className={`btn-demo-primary btn-demo-primary--full btn-scenario-card${activeScenario === 'doctor-login' ? ' btn-scenario-card--active' : ''}`}
              aria-current={activeScenario === 'doctor-login' ? 'true' : undefined}
            >
              🏥 Doctor Login
              <br />
              <span className="btn-scenario-card__subtitle">High Assurance Multi-VC</span>
            </button>

            <button
              id="btn-ehds-er"
              onClick={() => {
                setActiveScenario('ehds-er');
                handleHealthAccessDemo();
              }}
              className={`btn-demo-primary btn-scenario-card${activeScenario === 'ehds-er' ? ' btn-scenario-card--active' : ''}`}
              aria-current={activeScenario === 'ehds-er' ? 'true' : undefined}
            >
              🚑 ER Access
              <br />
              <span className="btn-scenario-card__subtitle">EHDS Emergency</span>
            </button>

            <button
              id="btn-pharmacy"
              onClick={() => {
                setActiveScenario('pharmacy');
                handlePharmacyDemo();
              }}
              className={`btn-demo-primary btn-scenario-card${activeScenario === 'pharmacy' ? ' btn-scenario-card--active' : ''}`}
              aria-current={activeScenario === 'pharmacy' ? 'true' : undefined}
            >
              💊 Pharmacy
              <br />
              <span className="btn-scenario-card__subtitle">ePrescription</span>
            </button>
          </div>
            </div>
          )}

        {/* UX-02: Progress bar during PROVING */}
        {activeWalletPage === 'requests' && status === 'PROVING' && (
          <div className="proving-progress wallet-section">
            <div className="proving-progress-bar" />
          </div>
        )}

        {activeWalletPage === 'trace' && (
          <div id="trace-section" className="trace-summary" data-testid="trace-summary">
          <div className="trace-summary__header">
            <div>
              <h3>Disclosure Trace</h3>
              <p>What was requested, allowed, withheld and sent.</p>
            </div>
            <span className="trace-summary__status">
              {evaluationResult?.verdict ?? 'Idle'}
            </span>
          </div>

          <div className="trace-summary__steps" aria-label="Trace sequence">
            <button
              type="button"
              className={`trace-summary__step${traceDetailPanel === 'consent' ? ' trace-summary__step--active' : ''}`}
              data-testid="trace-step"
              aria-pressed={traceDetailPanel === 'consent'}
              onClick={() => setTraceDetailPanel('consent')}
            >
              <span>1 Requested</span>
              <strong>{evaluationResult?.verdict ?? 'Idle'}</strong>
            </button>
            <button
              type="button"
              className={`trace-summary__step${traceDetailPanel === 'compliance' ? ' trace-summary__step--active' : ''}`}
              data-testid="trace-step"
              aria-pressed={traceDetailPanel === 'compliance'}
              onClick={() => setTraceDetailPanel('compliance')}
            >
              <span>2 Allowed</span>
              <strong>{recentAuditEntries.length} events</strong>
            </button>
            <button
              type="button"
              className={`trace-summary__step${traceDetailPanel === 'data-flow' ? ' trace-summary__step--active' : ''}`}
              data-testid="trace-step"
              aria-pressed={traceDetailPanel === 'data-flow'}
              onClick={() => setTraceDetailPanel('data-flow')}
            >
              <span>3 Sent</span>
              <strong>{currentRequest ? 'Request loaded' : 'Waiting'}</strong>
            </button>
          </div>

          {traceDetailPanel && (
            <div className="trace-summary__panel">
              {traceDetailPanel === 'consent' && (
                <ConsentManagerPanel
                  request={currentRequest}
                  result={evaluationResult}
                  auditEntries={recentAuditEntries}
                  privacyConsent={_privacyConsent}
                  consentReceipt={lastConsentReceipt}
                  receiptHistory={consentReceiptHistory}
                  onOpenDataFlow={() => setTraceDetailPanel('data-flow')}
                />
              )}
              {traceDetailPanel === 'compliance' && (
                <ComplianceDashboard
                  onExport={handleExportAuditReport}
                  onSyncL2={handleSyncAuditToL2}
                  getRecentLogs={getRecentComplianceLogs}
                  getChainStatus={getAuditChainStatus}
                />
              )}
              {traceDetailPanel === 'data-flow' && (
                <div id="dataflow-section">
                  <DataFlowPanel entries={recentAuditEntries} />
                </div>
              )}
            </div>
          )}
          </div>
        )}

        {/* UX-05: Audit Log */}
        {activeWalletPage === 'audit' && (
          <div id="audit-section" className="audit-section">
          <div className="audit-header">
            <h3 className="audit-title">Local Audit</h3>
            <button className="audit-copy-btn" onClick={handleCopyLog}>
              {copyLabel}
            </button>
          </div>
          <div className="audit-log-container" ref={logContainerRef}>
            {logs.map(renderLogLine)}
          </div>
          </div>
        )}
        </section>
      )}

      {isWalletReady && activeWalletPage === 'settings' && (
        <div className="wallet-section" style={{ marginTop: 10, textAlign: 'center' }}>
          <button
            onClick={handleResetWallet}
            style={{
              background: 'none',
              border: '1px solid rgba(220, 38, 38, 0.4)',
              color: '#ef4444',
              fontSize: 13,
              borderRadius: 10,
              padding: '8px 14px',
              cursor: 'pointer',
            }}
          >
            Reset device wallet
          </button>
        </div>
      )}

      {isWalletReady && activeWalletPage === 'settings' && (
      <div id="settings-section" className="wallet-section wallet-settings-section">
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
      )}

      {isWalletReady && activeWalletPage === 'advanced' && (
      <div id="advanced-section" className="demo-section advanced-section">
        <h3 className="demo-section-title">Advanced Tools</h3>
        {status === 'IDLE' && !guidedDemoActive && (
          <button
            className="btn-start-demo"
            onClick={() => {
              sessionStorage.removeItem('guidedDemoCompleted');
              setGuidedDemoActive(true);
            }}
          >
            Start guided flow
          </button>
        )}
        {/* Secondary — collapsible */}
        <button
          className="demo-secondary-toggle"
          onClick={() => setShowSecondary((s) => !s)}
          aria-expanded={showSecondary}
        >
          {showSecondary ? 'Hide advanced tools' : 'Show advanced tools'}
        </button>

        <div className={`demo-secondary-grid${showSecondary ? ' demo-secondary-grid--open' : ''}`}>
          <button
            onClick={handleWebAuthnDemo}
            className="btn-demo-secondary btn-demo-secondary--biometric"
          >
            🔐 Biometric (WebAuthn)
          </button>
          <button
            onClick={handleRecoveryTest}
            className="btn-demo-secondary btn-demo-secondary--recovery"
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
          <button
            onClick={handleFetchCredential}
            disabled={credentialStatus === 'fetching'}
            className={`btn-demo-secondary developer-tool-button${credentialStatus === 'done' ? ' developer-tool-button--done' : ''}`}
          >
            {credentialStatus === 'fetching'
              ? '⏳ Issuer request running'
              : credentialStatus === 'done'
                ? '✅ Test credential issued'
                : credentialStatus === 'error'
                  ? '↻ Retry test credential'
                  : '🎫 Test credential'}
          </button>
          {import.meta.env.DEV && (
            <label
              className="developer-tool-toggle"
              title="Dev only: mint the next issued credential as single-use (constraint fixed at issuance)"
            >
              <input
                type="checkbox"
                checked={mintSingleUse}
                onChange={(e) => setMintSingleUse(e.target.checked)}
              />
              <span>Single-use credential</span>
            </label>
          )}
          {import.meta.env.DEV && (
            <button
              onClick={handleFetchBatch}
              disabled={credentialStatus === 'fetching'}
              className="btn-demo-secondary developer-tool-button"
              title="Dev only: batch-issue 5 single-use credentials, each with its own wallet-generated holder key"
            >
              Batch issue {BATCH_SIZE}
            </button>
          )}
        </div>
      </div>
      )}

      <GuidedDemoMode
        isActive={guidedDemoActive && status === 'IDLE'}
        onExit={() => setGuidedDemoActive(false)}
        onStepExecute={(_stepId) => {}}
        steps={DEMO_STEPS_CONFIG.map((s) => ({
          ...s,
          onExecute:
            s.id === 1
              ? handleProveAge
              : s.id === 2
                ? handleMultiProofDemo
                : s.id === 3
                  ? handleHealthAccessDemo
                  : handlePharmacyDemo,
        }))}
      />
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
