/**
 * GuidedDemoMode.tsx — UX-07 Polish
 *
 * Improvements:
 * - Slide left/right transition between steps
 * - Progress bar: step X / N, animated dots
 * - Confetti burst on step completion
 * - Result summary shown after step execution
 * - "What the Verifier sees" visual diff (green vs strikethrough red)
 */

import { useState, useEffect, useRef } from 'react';
import { ReasonCode } from '@mitch/policy-engine';

// ── Types ─────────────────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────────

function verdictColor(verdict: DemoStep['expectedVerdict']): string {
  switch (verdict) {
    case 'ALLOW': return '#1b5e20';
    case 'PROMPT+BIOMETRIC': return '#4a148c';
    case 'PROMPT': return '#e65100';
  }
}

// ── Confetti (pure CSS + JS, no library) ─────────────────────────────────────

function launchConfetti(container: HTMLElement) {
  const colors = ['#00e676', '#00bfff', '#ffd740', '#ff6b6b', '#c77dff'];
  for (let i = 0; i < 40; i++) {
    const el = document.createElement('div');
    const size = 6 + Math.random() * 8;
    const color = colors[Math.floor(Math.random() * colors.length)];
    const leftPct = 20 + Math.random() * 60; // confetti within center 60%
    const delay = Math.random() * 400;
    const duration = 600 + Math.random() * 800;

    el.style.cssText = `
      position: fixed;
      left: ${leftPct}%;
      top: 35%;
      width: ${size}px;
      height: ${size}px;
      background: ${color};
      border-radius: ${Math.random() > 0.5 ? '50%' : '2px'};
      pointer-events: none;
      z-index: 9999;
      opacity: 1;
      animation: confettiFall ${duration}ms ease-in ${delay}ms both;
    `;
    container.appendChild(el);
    setTimeout(() => el.remove(), delay + duration + 50);
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

export function GuidedDemoMode({
  isActive,
  onExit,
  onStepExecute,
  steps,
}: GuidedDemoModeProps) {
  const [stepIndex, setStepIndex] = useState(0);
  const [isExecuting, setIsExecuting] = useState(false);
  const [slideDir, setSlideDir] = useState<'enter' | 'exit-left' | 'exit-right' | null>(null);
  const [showResult, setShowResult] = useState(false);
  const confettiRef = useRef<HTMLDivElement>(null);

  // ── Highlight-Management ─────────────────────────────────────────────────
  useEffect(() => {
    if (!isActive || steps.length === 0) return;

    const currentStep = steps[stepIndex];
    if (!currentStep) return;

    document.querySelectorAll('.guided-highlight').forEach(el => {
      el.classList.remove('guided-highlight');
    });

    const targetBtn = document.getElementById(currentStep.buttonId);
    if (targetBtn) {
      targetBtn.classList.add('guided-highlight');
    }

    return () => {
      if (targetBtn) {
        targetBtn.classList.remove('guided-highlight');
      }
      document.querySelectorAll('.guided-highlight').forEach(el => {
        el.classList.remove('guided-highlight');
      });
    };
  }, [isActive, stepIndex, steps]);

  // ── Exit ──────────────────────────────────────────────────────────────────
  const handleExit = (_completed: boolean = false) => {
    document.querySelectorAll('.guided-highlight').forEach(el => {
      el.classList.remove('guided-highlight');
    });
    sessionStorage.setItem('guidedDemoCompleted', 'true');
    setStepIndex(0);
    setIsExecuting(false);
    setShowResult(false);
    onExit();
  };

  // ── Navigate steps with slide animation ──────────────────────────────────
  const goToStep = (nextIndex: number) => {
    const dir = nextIndex > stepIndex ? 'exit-left' : 'exit-right';
    setSlideDir(dir);
    setShowResult(false);
    setTimeout(() => {
      setStepIndex(nextIndex);
      setSlideDir('enter');
      setTimeout(() => setSlideDir(null), 280);
    }, 220);
  };

  // ── Execute step ──────────────────────────────────────────────────────────
  const handleExecute = async () => {
    if (isExecuting) return;
    const currentStep = steps[stepIndex];
    if (!currentStep) return;

    setIsExecuting(true);
    currentStep.onExecute();
    onStepExecute(currentStep.id);

    // Wait for execution
    await new Promise<void>(resolve => setTimeout(resolve, 1500));

    // Confetti + result summary
    if (confettiRef.current) {
      launchConfetti(confettiRef.current);
    }
    setShowResult(true);
    setIsExecuting(false);
  };

  // ── Next step ─────────────────────────────────────────────────────────────
  const handleNext = () => {
    if (stepIndex < steps.length - 1) {
      goToStep(stepIndex + 1);
    } else {
      handleExit(true);
    }
  };

  if (!isActive || steps.length === 0) return null;

  const currentStep = steps[stepIndex];

  const stepContentStyle: React.CSSProperties = {
    transition: 'opacity 0.22s ease, transform 0.22s ease',
    opacity: slideDir === 'enter' || slideDir === null ? 1 : 0,
    transform: slideDir === 'exit-left'
      ? 'translateX(-14px)'
      : slideDir === 'exit-right'
        ? 'translateX(14px)'
        : slideDir === 'enter'
          ? 'translateX(0)'
          : 'translateX(0)',
  };

  return (
    <>
      {/* Inline keyframes */}
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
        @keyframes confettiFall {
          0%   { transform: translateY(0) rotate(0deg); opacity: 1; }
          80%  { opacity: 0.8; }
          100% { transform: translateY(180px) rotate(360deg); opacity: 0; }
        }
      `}</style>

      {/* Confetti container */}
      <div ref={confettiRef} style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 9999 }} />

      {/* Backdrop */}
      <div style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.4)',
        zIndex: 90,
        pointerEvents: 'none',
      }} />

      {/* Bottom Sheet */}
      <div style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 100,
        pointerEvents: 'auto',
        background: '#0e0e0e',
        borderTop: '1px solid #1e1e1e',
        borderRadius: '22px 22px 0 0',
        padding: '18px 20px',
        paddingBottom: `calc(20px + env(safe-area-inset-bottom, 0px))`,
        maxHeight: '46vh',
        overflowY: 'auto',
        boxShadow: '0 -8px 48px rgba(0,0,0,0.7)',
      }}>

        {/* Progress Bar (UX-07) */}
        <div style={{ marginBottom: 14 }}>
          {/* Dots */}
          <div style={{ display: 'flex', gap: 5, justifyContent: 'center', marginBottom: 6 }}>
            {steps.map((_, i) => (
              <div key={i} style={{
                width: i === stepIndex ? 20 : 7,
                height: 7,
                borderRadius: 4,
                background: i === stepIndex ? '#00bfff' : (i < stepIndex ? '#2e7d32' : '#1e1e1e'),
                transition: 'all 0.3s ease',
                cursor: i < stepIndex ? 'pointer' : 'default',
              }}
                onClick={() => i < stepIndex && goToStep(i)}
              />
            ))}
          </div>
          {/* Linear progress */}
          <div style={{ height: 2, background: '#1a1a1a', borderRadius: 1, overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${((stepIndex + 1) / steps.length) * 100}%`,
              background: 'linear-gradient(90deg, #0070f3, #00bfff)',
              borderRadius: 1,
              transition: 'width 0.35s ease',
            }} />
          </div>
        </div>

        {/* Slide-animated step content */}
        <div style={stepContentStyle}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{ fontSize: 16, fontWeight: 700, color: '#fff' }}>
              {currentStep.scenario}
            </span>
            <span style={{
              fontSize: 9, padding: '2px 7px', borderRadius: 4, fontWeight: 700,
              background: verdictColor(currentStep.expectedVerdict),
              color: '#fff', letterSpacing: 0.5,
            }}>
              {currentStep.expectedVerdict}
            </span>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: '#444', whiteSpace: 'nowrap' }}>
              {stepIndex + 1} / {steps.length}
            </span>
          </div>

          <div style={{ fontSize: 14, fontWeight: 600, color: '#ddd', marginBottom: 5 }}>
            {currentStep.title}
          </div>

          <div style={{ fontSize: 12, color: '#777', lineHeight: 1.6, marginBottom: 12 }}>
            {currentStep.description}
          </div>

          {/* Visual diff: Verifier sees vs blocked */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr',
            gap: 8, marginBottom: 14,
          }}>
            <div style={{
              background: '#071407', padding: '9px 11px',
              borderRadius: 10, borderLeft: '3px solid #2e7d32',
            }}>
              <div style={{ fontSize: 9, color: '#444', marginBottom: 4, letterSpacing: 1 }}>
                VERIFIER GETS
              </div>
              <div style={{ fontSize: 11, color: '#81c784', lineHeight: 1.6 }}>
                {currentStep.whatVerifierSees}
              </div>
            </div>
            <div style={{
              background: '#140707', padding: '9px 11px',
              borderRadius: 10, borderLeft: '3px solid #b71c1c',
            }}>
              <div style={{ fontSize: 9, color: '#444', marginBottom: 4, letterSpacing: 1 }}>
                BLOCKED ✗
              </div>
              <div style={{ fontSize: 11, color: '#e57373', lineHeight: 1.6, textDecoration: 'line-through', opacity: 0.8 }}>
                {currentStep.whatIsBlocked}
              </div>
            </div>
          </div>

          {/* UX-07: Result summary after execution */}
          {showResult && (
            <div style={{
              background: 'rgba(0, 230, 118, 0.08)',
              border: '1px solid rgba(0, 230, 118, 0.2)',
              borderRadius: 10, padding: '10px 14px',
              marginBottom: 12,
              fontSize: 12, color: '#a5d6a7',
              display: 'flex', alignItems: 'center', gap: 8,
              animation: 'mitchFadeIn 0.3s ease-out',
            }}>
              <span style={{ fontSize: 16 }}>✅</span>
              <span>
                <strong>Step {stepIndex + 1} complete!</strong> The proof was generated. {
                  stepIndex < steps.length - 1
                    ? 'Ready for next scenario.'
                    : 'All scenarios complete! 🎉'
                }
              </span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {stepIndex > 0 && !showResult && (
            <button
              onClick={() => !isExecuting && goToStep(stepIndex - 1)}
              disabled={isExecuting}
              style={{
                padding: '10px 14px',
                background: '#111', border: '1px solid #222',
                borderRadius: 8, color: '#888',
                cursor: isExecuting ? 'not-allowed' : 'pointer',
                fontSize: 13, minHeight: 44,
              }}>
              ← Back
            </button>
          )}

          {showResult ? (
            <button
              onClick={handleNext}
              style={{
                flex: 1, padding: '12px 16px',
                background: stepIndex === steps.length - 1
                  ? 'linear-gradient(135deg, #2e7d32, #1b5e20)'
                  : 'linear-gradient(135deg, #0070f3, #005fd3)',
                border: 'none',
                borderRadius: 8, color: '#fff',
                cursor: 'pointer',
                fontWeight: 700, fontSize: 14,
                transition: 'all 0.2s', minHeight: 44,
              }}>
              {stepIndex === steps.length - 1 ? '🎉 Finish Demo' : '→ Next Scenario'}
            </button>
          ) : (
            <button
              onClick={handleExecute}
              disabled={isExecuting}
              style={{
                flex: 1, padding: '12px 16px',
                background: isExecuting ? '#111' : 'linear-gradient(135deg, #0070f3, #005fd3)',
                border: isExecuting ? '1px solid #222' : 'none',
                borderRadius: 8, color: isExecuting ? '#555' : '#fff',
                cursor: isExecuting ? 'not-allowed' : 'pointer',
                fontWeight: 700, fontSize: 14,
                transition: 'all 0.2s', minHeight: 44,
              }}>
              {isExecuting
                ? <><span className="evaluating-spinner" style={{ borderTopColor: '#555' }} />Running...</>
                : '▶ Run Scenario'}
            </button>
          )}

          <button
            onClick={() => handleExit(false)}
            style={{
              padding: '10px 12px',
              background: 'transparent', border: '1px solid #1a1a1a',
              borderRadius: 8, color: '#333',
              cursor: 'pointer', fontSize: 11,
              whiteSpace: 'nowrap', minHeight: 44,
            }}>
            Skip
          </button>
        </div>

      </div>
    </>
  );
}

// Re-exported for App.tsx convenience
export { ReasonCode };
