/**
 * ConsentModal.tsx
 *
 * Ersetzt den inline `{showConsent && ...}` Block in App.tsx.
 *
 * Zeigt den DecisionCapsule-Inhalt in der "Secure Decision Boundary"
 * (T-24) an und orchestriert den WebAuthn-Flow wenn `requires_presence`.
 *
 * Flow:
 *   PROMPT
 *     ↓
 *   [ConsentModal öffnet]
 *     ↓
 *   User liest: Wer fragt? Was wird freigegeben? Warum?
 *     ↓
 *   requires_presence?
 *     ja → [Biometrie-Button sichtbar]
 *            ↓
 *            navigator.credentials.get (WebAuthn Ceremony)
 *            ↓
 *            presenceVerified = true
 *            ↓
 *     → [Sign & Authorize aktiviert]
 *     nein → [Sign & Authorize direkt aktiv]
 *     ↓
 *   onApprove(presenceProof?)
 *
 * Props:
 *   capsule       - DecisionCapsule aus PolicyEngine
 *   reasonCodes   - Array<ReasonCode> zur Anzeige
 *   onApprove     - Callback bei Zustimmung (mit optionalem PresenceProof)
 *   onReject      - Callback bei Ablehnung
 */

import { useState, useCallback } from 'react';
import { DecisionCapsule } from '@mitch/shared-types';
import { WebAuthnService } from '@mitch/shared-crypto';
import { ReasonCode } from '@mitch/policy-engine';
import { SecureZone } from './SecureZone';
import { translateReason, translateClaim } from '../utils/i18n';

// ── Typen ────────────────────────────────────────────────────────────────────

interface ConsentModalProps {
  capsule: DecisionCapsule;
  reasonCodes: string[];
  timeoutMinutes?: number;
  onApprove: (presenceProof?: string) => void;
  onReject: () => void;
  onLog?: (msg: string, type: 'info' | 'success' | 'warning' | 'error') => void;
}

type BiometricState = 'idle' | 'pending' | 'verified' | 'failed';

// ── Hilfsfunktionen ──────────────────────────────────────────────────────────

function humanReadableReason(code: string): string {
  return translateReason(code);
}

function riskColor(level: string | undefined): string {
  switch (level) {
    case 'HIGH': return '#E53935';
    case 'MEDIUM': return '#F57C00';
    default: return '#2e7d32';
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export function ConsentModal({ capsule, reasonCodes, timeoutMinutes, onApprove, onReject, onLog }: ConsentModalProps) {

  const [biometricState, setBiometricState] = useState<BiometricState>('idle');
  const [presenceProof, setPresenceProof] = useState<string | undefined>(undefined);

  const requiresPresence = (capsule as any).requires_presence === true
    || capsule.risk_level === 'HIGH';

  const canApprove = !requiresPresence || biometricState === 'verified';

  // ── WebAuthn Ceremony ──────────────────────────────────────────────────────
  const handleBiometricChallenge = useCallback(async () => {
    setBiometricState('pending');
    onLog?.('👤 Starte biometrische Verifikation...', 'info');

    try {
      // Passkeys are now auto-registered at App launch.
      // We assume it's there. If cross-device is used without a passkey on *this* device, it will fall back to QR/PIN automatically.
      const proof = await WebAuthnService.provePresenceDetailed(capsule.decision_id, timeoutMinutes || 0);
      setPresenceProof(proof.signature);
      setBiometricState('verified');
      onLog?.('✅ Biometrie bestätigt — Anwesenheit kryptographisch gebunden', 'success');

    } catch (err) {
      const errObj = err as Error;
      const msg = errObj.message;
      const errName = errObj.name;
      setBiometricState('failed');

      if (msg.includes('CANCELLED') || errName === 'NotAllowedError') {
        onLog?.('⚠️  Biometrie abgebrochen oder Timeout erreicht (60s).', 'warning');
      } else {
        onLog?.(`❌ Biometrie fehlgeschlagen: ${msg}`, 'error');
      }
    }
  }, [capsule.decision_id, onLog]);

  // ── Render ─────────────────────────────────────────────────────────────────

  const verifierShort = capsule.verifier_did.length > 40
    ? capsule.verifier_did.substring(0, 40) + '…'
    : capsule.verifier_did;

  const decisionShort = capsule.decision_id.substring(0, 18) + '…';

  // Device detection for dynamic icon
  const getBiometricIcon = () => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('windows')) return '👤'; // Face ID or Windows Hello
    if (ua.includes('mac') || ua.includes('android')) return '👆'; // Touch ID or Fingerprint
    return '🔑'; // Generic Fallback
  };
  const bioIcon = getBiometricIcon();

  return (
    <div className="secure-backdrop">
      <div className="secure-prompt" style={{
        borderTop: `4px solid ${riskColor(capsule.risk_level)}`
      }}>

        {/* ── Header ──────────────────────────────────────────────────── */}
        <div className="secure-header">
          <span className="secure-badge">WALLET DECISION BOUNDARY</span>
          <div style={{ flex: 1 }} />
          <div style={{
            width: 12, height: 12, borderRadius: '50%',
            background: 'var(--accent-green)',
            boxShadow: '0 0 10px var(--accent-green)'
          }} />
        </div>

        <h2 style={{ fontSize: 22, margin: '12px 0 6px 0' }}>
          🔐 Datenfreigabe-Anfrage
        </h2>

        {/* ── Verifier ────────────────────────────────────────────────── */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: '#666', marginBottom: 4 }}>VERIFIER</div>
          <div style={{
            background: '#111', padding: '8px 12px', borderRadius: 8,
            fontFamily: 'monospace', color: 'var(--accent-blue)', fontSize: 13,
            wordBreak: 'break-all'
          }}>
            {verifierShort}
          </div>
        </div>

        {/* ── Warum PROMPT? (ReasonCodes) ──────────────────────────────── */}
        {reasonCodes.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: '#666', marginBottom: 4 }}>GRUND DER ANFRAGE</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {reasonCodes.map(code => (
                <div key={code} style={{
                  background: '#1a1a1a', padding: '6px 10px', borderRadius: 6,
                  fontSize: 13, color: '#ccc',
                  borderLeft: `3px solid ${riskColor(capsule.risk_level)}`
                }}>
                  {humanReadableReason(code)}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Erlaubte Daten (was würde freigegeben) ───────────────────── */}
        <div style={{ background: '#000', padding: 14, borderRadius: 10, marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: '#666', marginBottom: 8 }}>
            WÜRDE FREIGEGEBEN (strikt auf diese Daten begrenzt)
          </div>

          {/* Multi-VC: authorized_requirements */}
          {(capsule as any).authorized_requirements?.map((req: any, i: number) => (
            <div key={i} style={{
              marginBottom: 10, paddingLeft: 10,
              borderLeft: '2px solid #333'
            }}>
              <div style={{ fontSize: 10, color: '#555', marginBottom: 4 }}>
                CREDENTIAL: {req.credential_type}
              </div>
              {req.proven_claims?.map((c: string) => (
                <div key={c} style={{
                  fontSize: 14, color: 'var(--accent-green)',
                  display: 'flex', alignItems: 'center', gap: 6
                }}>
                  ✅ NACHWEIS: {translateClaim(c)}
                </div>
              ))}
              {req.allowed_claims?.map((c: string) => (
                <div key={c} style={{
                  fontSize: 14, color: 'var(--accent-yellow)',
                  display: 'flex', alignItems: 'center', gap: 6
                }}>
                  ⚠️  ROHDATEN: {translateClaim(c)}
                </div>
              ))}
            </div>
          ))}

          {/* Legacy single-VC */}
          {!(capsule as any).authorized_requirements && (<>
            {(capsule as any).proven_claims?.map((c: string) => (
              <div key={c} style={{ fontSize: 14, color: 'var(--accent-green)', marginBottom: 4 }}>
                ✅ NACHWEIS: {translateClaim(c)}
              </div>
            ))}
            {(capsule as any).allowed_claims?.map((c: string) => (
              <div key={c} style={{ fontSize: 14, color: 'var(--accent-yellow)', marginBottom: 4 }}>
                ⚠️  ROHDATEN: {translateClaim(c)}
              </div>
            ))}
          </>)}

          {/* Wenn keine Daten → rein ZKP */}
          {!(capsule as any).proven_claims?.length &&
            !(capsule as any).allowed_claims?.length &&
            !(capsule as any).authorized_requirements?.length && (
              <div style={{ fontSize: 13, color: '#888' }}>
                Nur kryptographische Nachweise — keine Rohdaten
              </div>
            )}
        </div>

        {/* ── Security Checksum ────────────────────────────────────────── */}
        <div style={{
          fontSize: 11, color: '#444', fontFamily: 'monospace',
          marginBottom: 20
        }}>
          DECISION: {decisionShort} &nbsp;|&nbsp;
          RISK: <span style={{ color: riskColor(capsule.risk_level) }}>
            {capsule.risk_level ?? 'LOW'}
          </span>
        </div>

        {/* ── WebAuthn Block (nur wenn requires_presence) ──────────────── */}
        {requiresPresence && (
          <div style={{
            background: '#0a0a1a',
            border: `1px solid ${biometricState === 'verified' ? '#2e7d32' : '#333'}`,
            borderRadius: 12, padding: 16, marginBottom: 20
          }}>
            <div style={{ fontSize: 12, color: '#888', marginBottom: 8 }}>
              🔐 BIOMETRISCHE ANWESENHEIT ERFORDERLICH (Layer 2)
            </div>
            <div style={{ fontSize: 13, color: '#ccc', marginBottom: 12 }}>
              Diese Anfrage enthält sensible Daten. Bestätige mit Fingerabdruck,
              Gesichtserkennung oder Geräte-PIN.
            </div>

            {biometricState === 'idle' && (
              <button
                onClick={handleBiometricChallenge}
                style={{
                  width: '100%', padding: 14,
                  background: '#1a237e', border: '1px solid #3949ab',
                  borderRadius: 10, color: '#fff',
                  fontSize: 15, fontWeight: 700, cursor: 'pointer'
                }}
              >
                {bioIcon} Jetzt verifizieren
              </button>
            )}

            {biometricState === 'pending' && (
              <div style={{
                textAlign: 'center', padding: 14,
                color: '#7986cb', fontSize: 14, animation: 'pulse 1.5s infinite'
              }}>
                ⏳ Warte auf Biometrie...
              </div>
            )}

            {biometricState === 'verified' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                color: 'var(--accent-green)', fontWeight: 700, fontSize: 14
              }}>
                ✅ Anwesenheit bestätigt &nbsp;
                <span style={{ fontSize: 11, color: '#555', fontFamily: 'monospace' }}>
                  {presenceProof?.substring(0, 12)}…
                </span>
              </div>
            )}

            {biometricState === 'failed' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ color: '#E53935', fontSize: 13 }}>
                  ❌ Verifikation fehlgeschlagen
                </div>
                <button
                  onClick={handleBiometricChallenge}
                  style={{
                    padding: 10, background: 'transparent',
                    border: '1px solid #555', borderRadius: 8,
                    color: '#aaa', cursor: 'pointer', fontSize: 13
                  }}
                >
                  Erneut versuchen
                </button>
              </div>
            )}
          </div>
        )}

        {/* ── Aktions-Buttons ──────────────────────────────────────────── */}
        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={onReject}
            style={{
              flex: 1, padding: 14,
              background: '#1a1a1a', border: '1px solid #444',
              borderRadius: 12, color: '#fff',
              fontWeight: 600, cursor: 'pointer', fontSize: 14
            }}
          >
            Ablehnen
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
              title={
                !canApprove
                  ? 'Biometrie erforderlich — bitte zuerst verifizieren'
                  : 'Freigabe bestätigen'
              }
              style={{
                width: '100%', height: '100%', padding: 14,
                background: canApprove ? 'var(--accent-blue)' : '#333',
                border: 'none', borderRadius: 12,
                color: canApprove ? '#000' : '#666',
                fontWeight: 800, cursor: canApprove ? 'pointer' : 'not-allowed',
                fontSize: 14, transition: 'all 0.2s',
                boxShadow: canApprove
                  ? '0 10px 20px rgba(0, 191, 255, 0.3)'
                  : 'none',
              }}
            >
              {requiresPresence && biometricState !== 'verified'
                ? '🔒 Biometrie fehlt'
                : '✅ Freigabe bestätigen'}
            </button>
          </SecureZone>
        </div>

        <div style={{
          marginTop: 16, textAlign: 'center',
          fontSize: 11, color: '#444'
        }}>
          🛡️ Entscheidung ist kryptographisch an diese Session gebunden
          &nbsp;·&nbsp; Ablauf in 5 min
        </div>

      </div>
    </div>
  );
}
