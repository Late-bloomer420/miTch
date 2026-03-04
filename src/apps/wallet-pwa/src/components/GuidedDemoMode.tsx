/**
 * GuidedDemoMode.tsx
 *
 * Bottom-Sheet-Overlay das Stakeholder durch alle 4 Demo-Szenarien führt.
 *
 * WICHTIG — Import-Regeln:
 *   ReasonCode kommt aus @mitch/policy-engine (NICHT aus @mitch/layer-resolver)
 *   layer-resolver ist ein internes Infrastruktur-Paket — nie direkt in UI importieren
 */

import { useState, useEffect } from 'react';

// ── Korrekte Import-Pfade ────────────────────────────────────────────────────
// ReasonCode aus policy-engine (dort re-exportiert)
// KEIN Import aus @mitch/layer-resolver in UI-Components!
import { ReasonCode } from '@mitch/policy-engine';

// ── Typen ────────────────────────────────────────────────────────────────────

export interface DemoStep {
  id: number;
  scenario: string;
  title: string;
  description: string;
  whatVerifierSees: string;
  whatIsBlocked: string;
  buttonId: string;
  expectedVerdict: 'ALLOW' | 'PROMPT' | 'PROMPT+BIOMETRIC';
  onExecute: () => void;
}

interface GuidedDemoModeProps {
  isActive: boolean;
  onExit: () => void;
  onStepExecute: (stepId: number) => void;
  steps: DemoStep[];
}

// ── Helper ───────────────────────────────────────────────────────────────────

function verdictColor(verdict: DemoStep['expectedVerdict']): string {
  switch (verdict) {
    case 'ALLOW':            return '#1b5e20';
    case 'PROMPT+BIOMETRIC': return '#4a148c';
    case 'PROMPT':           return '#e65100';
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export function GuidedDemoMode({
  isActive,
  onExit,
  onStepExecute,
  steps,
}: GuidedDemoModeProps) {
  const [stepIndex, setStepIndex] = useState(0);
  const [isExecuting, setIsExecuting] = useState(false);

  // ── Highlight-Management via useEffect ──────────────────────────────────
  // Immer in useEffect — nicht inline — damit cleanup garantiert läuft.
  useEffect(() => {
    if (!isActive || steps.length === 0) return;

    const currentStep = steps[stepIndex];
    if (!currentStep) return;

    // Erst alle alten Highlights entfernen (Sicherheitsnetz)
    document.querySelectorAll('.guided-highlight').forEach(el => {
      el.classList.remove('guided-highlight');
    });

    // Neuen Highlight setzen — fail-closed: kein Crash wenn Button nicht im DOM
    const targetBtn = document.getElementById(currentStep.buttonId);
    if (targetBtn) {
      targetBtn.classList.add('guided-highlight');
    }

    // Cleanup bei Step-Wechsel oder Unmount
    return () => {
      if (targetBtn) {
        targetBtn.classList.remove('guided-highlight');
      }
      // Sicherheitsnetz: alle verbleibenden Highlights entfernen
      document.querySelectorAll('.guided-highlight').forEach(el => {
        el.classList.remove('guided-highlight');
      });
    };
  }, [isActive, stepIndex, steps]);

  // ── Exit-Handler ─────────────────────────────────────────────────────────
  const handleExit = (_completed: boolean = false) => {
    // Highlights entfernen
    document.querySelectorAll('.guided-highlight').forEach(el => {
      el.classList.remove('guided-highlight');
    });
    // SessionStorage IMMER setzen — auch bei Skip
    // (Stakeholder sollen beim zweiten Laden nicht erneut gestört werden)
    sessionStorage.setItem('guidedDemoCompleted', 'true');
    setStepIndex(0);
    setIsExecuting(false);
    onExit();
  };

  // ── Execute-Handler ───────────────────────────────────────────────────────
  const handleExecute = async () => {
    if (isExecuting) return; // Doppelklick-Guard
    const currentStep = steps[stepIndex];
    if (!currentStep) return;

    setIsExecuting(true);
    currentStep.onExecute();
    onStepExecute(currentStep.id);

    // Warte 1500ms damit User das Ergebnis im Wallet sieht
    await new Promise<void>(resolve => setTimeout(resolve, 1500));

    if (stepIndex < steps.length - 1) {
      setStepIndex(prev => prev + 1);
    } else {
      // Letzter Step — Demo vollständig
      handleExit(true);
    }
    setIsExecuting(false);
  };

  if (!isActive || steps.length === 0) return null;

  const currentStep = steps[stepIndex];

  return (
    <>
      {/* Inline Keyframes + Highlight-Klasse — kein externes CSS-File */}
      <style>{`
        @keyframes guidedPulse {
          0%   { box-shadow: 0 0 0 0px rgba(0, 191, 255, 0.7); }
          70%  { box-shadow: 0 0 0 8px rgba(0, 191, 255, 0); }
          100% { box-shadow: 0 0 0 0px rgba(0, 191, 255, 0); }
        }
        .guided-highlight {
          animation: guidedPulse 1.5s ease-out infinite !important;
          outline: 2px solid #00bfff !important;
          outline-offset: 2px;
        }
      `}</style>

      {/* Backdrop — pointer-events: none damit Wallet dahinter klickbar bleibt */}
      <div style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.45)',
        zIndex: 90,
        pointerEvents: 'none',
      }} />

      {/* Bottom Sheet — pointer-events: auto für Interaktion */}
      <div style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 100,
        pointerEvents: 'auto',
        background: '#111',
        borderTop: '1px solid #222',
        borderRadius: '24px 24px 0 0',
        padding: '20px 24px 32px',
        maxHeight: '44vh',
        overflowY: 'auto',
        boxShadow: '0 -4px 40px rgba(0,0,0,0.6)',
      }}>

        {/* Progress Dots */}
        <div style={{ display: 'flex', gap: 6, justifyContent: 'center', marginBottom: 18 }}>
          {steps.map((_, i) => (
            <div key={i} style={{
              width: i === stepIndex ? 22 : 8,
              height: 8,
              borderRadius: 4,
              background: i === stepIndex ? '#00bfff' : (i < stepIndex ? '#2e7d32' : '#2a2a2a'),
              transition: 'all 0.3s ease',
            }} />
          ))}
        </div>

        {/* Scenario + Verdict Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 18, fontWeight: 700, color: '#fff' }}>
            {currentStep.scenario}
          </span>
          <span style={{
            fontSize: 10, padding: '2px 8px', borderRadius: 4, fontWeight: 700,
            background: verdictColor(currentStep.expectedVerdict),
            color: '#fff', letterSpacing: 0.5,
          }}>
            {currentStep.expectedVerdict}
          </span>
          <span style={{ marginLeft: 'auto', fontSize: 11, color: '#444' }}>
            {stepIndex + 1} / {steps.length}
          </span>
        </div>

        {/* Title */}
        <div style={{ fontSize: 15, fontWeight: 600, color: '#e0e0e0', marginBottom: 6 }}>
          {currentStep.title}
        </div>

        {/* Description */}
        <div style={{ fontSize: 13, color: '#888', lineHeight: 1.6, marginBottom: 16 }}>
          {currentStep.description}
        </div>

        {/* Verifier-Sicht vs. Blockiert */}
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr',
          gap: 10, marginBottom: 18,
        }}>
          <div style={{
            background: '#0a1a0a', padding: '10px 12px',
            borderRadius: 10, borderLeft: '3px solid #2e7d32',
          }}>
            <div style={{ fontSize: 10, color: '#555', marginBottom: 5, letterSpacing: 1 }}>
              VERIFIER ERHÄLT
            </div>
            <div style={{ fontSize: 12, color: '#81c784', lineHeight: 1.6 }}>
              {currentStep.whatVerifierSees}
            </div>
          </div>
          <div style={{
            background: '#1a0a0a', padding: '10px 12px',
            borderRadius: 10, borderLeft: '3px solid #b71c1c',
          }}>
            <div style={{ fontSize: 10, color: '#555', marginBottom: 5, letterSpacing: 1 }}>
              BLOCKIERT
            </div>
            <div style={{ fontSize: 12, color: '#e57373', lineHeight: 1.6 }}>
              {currentStep.whatIsBlocked}
            </div>
          </div>
        </div>

        {/* Aktions-Buttons */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
          {stepIndex > 0 && (
            <button
              onClick={() => !isExecuting && setStepIndex(prev => prev - 1)}
              disabled={isExecuting}
              style={{
                padding: '10px 16px',
                background: '#1a1a1a', border: '1px solid #333',
                borderRadius: 8, color: '#aaa',
                cursor: isExecuting ? 'not-allowed' : 'pointer',
                fontSize: 13,
              }}>
              ← Zurück
            </button>
          )}

          <button
            onClick={handleExecute}
            disabled={isExecuting}
            style={{
              flex: 1, padding: '12px 16px',
              background: isExecuting ? '#1a1a1a' : '#0070f3',
              border: isExecuting ? '1px solid #333' : 'none',
              borderRadius: 8, color: isExecuting ? '#555' : '#fff',
              cursor: isExecuting ? 'not-allowed' : 'pointer',
              fontWeight: 700, fontSize: 14,
              transition: 'all 0.2s',
            }}>
            {isExecuting
              ? '⏳ Ausführen...'
              : stepIndex === steps.length - 1
                ? '▶ Ausführen & Fertig'
                : '▶ Ausführen & Weiter'}
          </button>

          <button
            onClick={() => handleExit(false)}
            style={{
              padding: '10px 14px',
              background: 'transparent', border: '1px solid #222',
              borderRadius: 8, color: '#444',
              cursor: 'pointer', fontSize: 12,
              whiteSpace: 'nowrap',
            }}>
            Überspringen
          </button>
        </div>

      </div>
    </>
  );
}

// ReasonCode wird re-exportiert damit App.tsx ihn nicht direkt importieren muss
export { ReasonCode };
