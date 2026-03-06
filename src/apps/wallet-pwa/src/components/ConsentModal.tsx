/**
 * ConsentModal.tsx — UX-06 Polish
 *
 * Improvements:
 * - Entry animation: slides in from below (mobile-native)
 * - Risk banner prominently at top
 * - Claims as chips (green = allowed/ZKP, yellow = raw, red = blocked)
 * - WebAuthn button with pulsing animation
 * - Countdown ring when timeoutMinutes set
 * - Reject as text-link (less prominent than Approve)
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { DecisionCapsule } from '@mitch/shared-types';
import { WebAuthnService } from '@mitch/shared-crypto';
import { SecureZone } from './SecureZone';
import { translateReason, translateClaim } from '../utils/i18n';

// ── Types ─────────────────────────────────────────────────────────────────────

interface ConsentModalProps {
  capsule: DecisionCapsule;
  reasonCodes: string[];
  timeoutMinutes?: number;
  onApprove: (presenceProof?: string) => void;
  onReject: () => void;
  onLog?: (msg: string, type: 'info' | 'success' | 'warning' | 'error') => void;
}

type BiometricState = 'idle' | 'pending' | 'verified' | 'failed';

// ── Helpers ───────────────────────────────────────────────────────────────────

function riskColor(level: string | undefined): string {
  switch (level) {
    case 'HIGH': return '#E53935';
    case 'MEDIUM': return '#F57C00';
    default: return '#2e7d32';
  }
}

function riskBannerClass(level: string | undefined): string {
  switch (level) {
    case 'HIGH': return 'consent-risk-banner consent-risk-banner--high';
    case 'MEDIUM': return 'consent-risk-banner consent-risk-banner--medium';
    default: return 'consent-risk-banner consent-risk-banner--low';
  }
}

function riskLabel(level: string | undefined): string {
  switch (level) {
    case 'HIGH': return '⚠️ High Risk — Sensitive Data';
    case 'MEDIUM': return '⚡ Medium Risk — Review Before Approving';
    default: return '✅ Low Risk — Standard Disclosure';
  }
}

// ── Countdown Ring ────────────────────────────────────────────────────────────

function CountdownRing({ totalSeconds }: { totalSeconds: number }) {
  const [remaining, setRemaining] = useState(totalSeconds);
  const R = 13;
  const circumference = 2 * Math.PI * R; // ≈ 81.7

  useEffect(() => {
    if (totalSeconds <= 0) return;
    const interval = setInterval(() => {
      setRemaining(prev => {
        if (prev <= 1) { clearInterval(interval); return 0; }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [totalSeconds]);

  const progress = remaining / totalSeconds;
  const dashoffset = circumference * (1 - progress);

  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;
  const label = mins > 0 ? `${mins}m` : `${secs}s`;

  return (
    <div className="consent-countdown">
      <div className="countdown-ring">
        <svg width="32" height="32" viewBox="0 0 32 32">
          <circle cx="16" cy="16" r={R} fill="none" stroke="#222" strokeWidth="3" />
          <circle
            cx="16" cy="16" r={R}
            fill="none"
            stroke={remaining < 30 ? '#E53935' : 'var(--accent-blue)'}
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashoffset}
            className="countdown-ring-circle"
          />
        </svg>
        <div className="countdown-ring-text">{label}</div>
      </div>
      <span>Session expires in {remaining}s</span>
    </div>
  );
}

// ── Claim Chips ───────────────────────────────────────────────────────────────

function ClaimChips({ claims, variant }: {
  claims: string[];
  variant: 'allowed' | 'raw' | 'blocked';
}) {
  if (!claims || claims.length === 0) return null;
  const icons = { allowed: '✅', raw: '⚠️', blocked: '❌' };
  return (
    <div className="consent-chips-container">
      {claims.map(c => (
        <span key={c} className={`consent-chip consent-chip--${variant}`}>
          {icons[variant]} {translateClaim(c)}
        </span>
      ))}
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export function ConsentModal({ capsule, reasonCodes, timeoutMinutes, onApprove, onReject, onLog }: ConsentModalProps) {

  const [biometricState, setBiometricState] = useState<BiometricState>('idle');
  const [presenceProof, setPresenceProof] = useState<string | undefined>(undefined);
  const promptRef = useRef<HTMLDivElement>(null);

  const requiresPresence = capsule.requires_presence === true
    || capsule.risk_level === 'HIGH';

  const canApprove = !requiresPresence || biometricState === 'verified';

  const handleBiometricChallenge = useCallback(async () => {
    setBiometricState('pending');
    onLog?.('👤 Starting biometric verification...', 'info');

    try {
      const proof = await WebAuthnService.provePresenceDetailed(capsule.decision_id, timeoutMinutes || 0);
      setPresenceProof(proof.signature);
      setBiometricState('verified');
      onLog?.('✅ Biometrics confirmed — presence cryptographically bound', 'success');
    } catch (err) {
      const errObj = err as Error;
      const msg = errObj.message;
      const errName = errObj.name;
      setBiometricState('failed');

      if (msg.includes('CANCELLED') || errName === 'NotAllowedError') {
        onLog?.('⚠️  Biometrics cancelled or timeout reached (60s).', 'warning');
      } else {
        onLog?.(`❌ Biometrics failed: ${msg}`, 'error');
      }
    }
  }, [capsule.decision_id, onLog, timeoutMinutes]);

  const verifierShort = capsule.verifier_did.length > 40
    ? capsule.verifier_did.substring(0, 40) + '…'
    : capsule.verifier_did;

  const decisionShort = capsule.decision_id.substring(0, 18) + '…';

  const getBiometricIcon = () => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('windows')) return '👤';
    if (ua.includes('mac') || ua.includes('android')) return '👆';
    return '🔑';
  };
  const bioIcon = getBiometricIcon();

  // Collect claims for chips display
  const provenClaims: string[] = [];
  const rawClaims: string[] = [];

  if (capsule.authorized_requirements) {
    for (const req of capsule.authorized_requirements) {
      (req.proven_claims || []).forEach((c: string) => provenClaims.push(c));
      (req.allowed_claims || []).forEach((c: string) => rawClaims.push(c));
    }
  } else {
    (capsule.proven_claims || []).forEach((c: string) => provenClaims.push(c));
    (capsule.allowed_claims || []).forEach((c: string) => rawClaims.push(c));
  }

  const hasNoClaims = provenClaims.length === 0 && rawClaims.length === 0;

  return (
    <div className="secure-backdrop">
      <div className="secure-prompt consent-sheet-enter" ref={promptRef} style={{
        borderTop: `4px solid ${riskColor(capsule.risk_level)}`
      }}>

        {/* UX-06: Risk Banner */}
        <div className={riskBannerClass(capsule.risk_level)}>
          {riskLabel(capsule.risk_level)}
        </div>

        {/* Header */}
        <div className="secure-header">
          <span className="secure-badge">WALLET DECISION BOUNDARY</span>
          <div style={{ flex: 1 }} />
          <div style={{
            width: 10, height: 10, borderRadius: '50%',
            background: 'var(--accent-green)',
            boxShadow: '0 0 8px var(--accent-green)'
          }} />
        </div>

        <h2 style={{ fontSize: 20, margin: '8px 0 6px 0' }}>
          🔐 Data Disclosure Request
        </h2>

        {/* Verifier */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: '#555', marginBottom: 4, letterSpacing: 1 }}>VERIFIER</div>
          <div style={{
            background: '#0a0a0a', padding: '8px 12px', borderRadius: 8,
            fontFamily: 'monospace', color: 'var(--accent-blue)', fontSize: 12,
            wordBreak: 'break-all', border: '1px solid #1a1a1a'
          }}>
            {verifierShort}
          </div>
        </div>

        {/* Reason Codes */}
        {reasonCodes.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, color: '#555', marginBottom: 6, letterSpacing: 1 }}>REASON</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {reasonCodes.map(code => (
                <div key={code} style={{
                  background: '#111', padding: '5px 10px', borderRadius: 6,
                  fontSize: 12, color: '#bbb',
                  borderLeft: `3px solid ${riskColor(capsule.risk_level)}`
                }}>
                  {translateReason(code)}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* UX-06: Claims as Chips */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: '#555', marginBottom: 8, letterSpacing: 1 }}>
            WOULD BE DISCLOSED (strictly limited)
          </div>

          {capsule.authorized_requirements?.map((req, i: number) => (
            <div key={i} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 10, color: '#444', marginBottom: 6 }}>
                {req.credential_type}
              </div>
              <ClaimChips claims={req.proven_claims || []} variant="allowed" />
              <ClaimChips claims={req.allowed_claims || []} variant="raw" />
            </div>
          ))}

          {!capsule.authorized_requirements && (
            <>
              <ClaimChips claims={provenClaims} variant="allowed" />
              <ClaimChips claims={rawClaims} variant="raw" />
            </>
          )}

          {hasNoClaims && (
            <span className="consent-chip consent-chip--allowed">
              ✅ ZKP only — no raw data
            </span>
          )}
        </div>

        {/* Security Checksum */}
        <div style={{
          fontSize: 10, color: '#333', fontFamily: 'monospace',
          marginBottom: 16
        }}>
          ID: {decisionShort} &nbsp;·&nbsp; RISK:&nbsp;
          <span style={{ color: riskColor(capsule.risk_level) }}>
            {capsule.risk_level ?? 'LOW'}
          </span>
        </div>

        {/* UX-06: WebAuthn Block with pulsing button */}
        {requiresPresence && (
          <div style={{
            background: '#07071a',
            border: `1px solid ${biometricState === 'verified' ? '#2e7d32' : 'rgba(57,73,171,0.4)'}`,
            borderRadius: 14, padding: 16, marginBottom: 18
          }}>
            <div style={{ fontSize: 11, color: '#666', marginBottom: 6, letterSpacing: 0.5 }}>
              🔐 BIOMETRIC PRESENCE REQUIRED (Layer 2)
            </div>
            <div style={{ fontSize: 13, color: '#aaa', marginBottom: 12 }}>
              High-sensitivity data. Confirm with fingerprint, Face ID, or device PIN.
            </div>

            {biometricState === 'idle' && (
              <button
                onClick={handleBiometricChallenge}
                className="btn-webauthn"
              >
                {bioIcon} Verify Now
              </button>
            )}

            {biometricState === 'pending' && (
              <div style={{
                textAlign: 'center', padding: 14,
                color: '#7986cb', fontSize: 14,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8
              }}>
                <span className="evaluating-spinner" style={{ borderTopColor: '#7986cb' }} />
                Waiting for biometrics...
              </div>
            )}

            {biometricState === 'verified' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                color: 'var(--accent-green)', fontWeight: 700, fontSize: 14
              }}>
                ✅ Presence confirmed&nbsp;
                <span style={{ fontSize: 10, color: '#444', fontFamily: 'monospace' }}>
                  {presenceProof?.substring(0, 12)}…
                </span>
              </div>
            )}

            {biometricState === 'failed' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ color: '#E53935', fontSize: 13 }}>
                  ❌ Verification failed
                </div>
                <button
                  onClick={handleBiometricChallenge}
                  style={{
                    padding: 10, background: 'transparent',
                    border: '1px solid #444', borderRadius: 8,
                    color: '#aaa', cursor: 'pointer', fontSize: 13
                  }}
                >
                  Try again
                </button>
              </div>
            )}
          </div>
        )}

        {/* UX-06: Action buttons — Approve prominent, Reject as text-link */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={onReject}
            className="btn-reject-link"
          >
            Decline
          </button>

          <SecureZone
            onIntervention={(reason) =>
              onLog?.(`🚨 Security Intervention: ${reason}`, 'error')
            }
            className="secure-action-wrapper"
            style={{ flex: 1 }}
          >
            <button
              onClick={() => canApprove && onApprove(presenceProof)}
              disabled={!canApprove}
              className="btn-approve"
              title={
                !canApprove
                  ? 'Biometrics required — verify first'
                  : 'Confirm disclosure'
              }
            >
              {requiresPresence && biometricState !== 'verified'
                ? '🔒 Biometrics Required'
                : '✅ Approve Disclosure'}
            </button>
          </SecureZone>
        </div>

        {/* UX-06: Countdown ring if timeout set */}
        {timeoutMinutes && timeoutMinutes > 0 && (
          <CountdownRing totalSeconds={timeoutMinutes * 60} />
        )}

        {!timeoutMinutes && (
          <div style={{
            marginTop: 14, textAlign: 'center',
            fontSize: 10, color: '#333'
          }}>
            🛡️ Decision cryptographically bound to this session · Expires in 5 min
          </div>
        )}

      </div>
    </div>
  );
}
