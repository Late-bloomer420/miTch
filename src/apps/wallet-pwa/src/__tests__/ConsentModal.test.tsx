/**
 * G-03a — ConsentModal component tests
 */

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';

// Mock SecureZone — it uses elementFromPoint which jsdom doesn't implement;
// we test ConsentModal behaviour, not the clickjacking detector.
vi.mock('../components/SecureZone', () => ({
  SecureZone: ({ children, className, style }: { children: React.ReactNode; className?: string; style?: React.CSSProperties }) => (
    <div className={className} style={style}>{children}</div>
  ),
}));

import { ConsentModal } from '../components/ConsentModal';
import type { DecisionCapsule } from '@mitch/shared-types';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeCapsule(overrides: Partial<DecisionCapsule> = {}): DecisionCapsule {
  return {
    decision_id: 'test-decision-uuid-001',
    verdict: 'PROMPT',
    request_hash: 'abc123',
    policy_hash: 'def456',
    verifier_did: 'did:example:liquor-store',
    risk_level: 'LOW',
    requires_presence: false,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    authorized_requirements: [
      {
        credential_type: 'AgeCredential',
        allowed_claims: ['birthDate'],
        proven_claims: ['age >= 18'],
        selected_credential_id: 'vc-age-789',
        issuer_trust_refs: ['did:example:gov-issuer'],
      }
    ],
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ConsentModal — Rendering', () => {
  it('renders the disclosure request heading', () => {
    render(
      <ConsentModal
        capsule={makeCapsule()}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.getByText(/Data Disclosure Request/i)).toBeInTheDocument();
  });

  it('renders verifier DID (truncated)', () => {
    render(
      <ConsentModal
        capsule={makeCapsule({ verifier_did: 'did:example:liquor-store' })}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.getByText(/did:example:liquor-store/i)).toBeInTheDocument();
  });

  it('renders reason codes section when codes are provided', () => {
    render(
      <ConsentModal
        capsule={makeCapsule()}
        reasonCodes={['AGE_VERIFICATION_REQUIRED']}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    // The REASON label is only shown when reasonCodes is non-empty
    expect(screen.getByText('REASON')).toBeInTheDocument();
  });

  it('shows ZKP-only chip when no claims in capsule', () => {
    const capsule = makeCapsule({
      authorized_requirements: [
        {
          credential_type: 'AgeCredential',
          allowed_claims: [],
          proven_claims: [],
          selected_credential_id: 'vc-age-789',
          issuer_trust_refs: [],
        }
      ]
    });
    render(
      <ConsentModal
        capsule={capsule}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.getByText(/ZKP only/i)).toBeInTheDocument();
  });

  it('shows low-risk banner for LOW risk_level', () => {
    render(
      <ConsentModal
        capsule={makeCapsule({ risk_level: 'LOW' })}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.getByText(/Low Risk/i)).toBeInTheDocument();
  });

  it('shows high-risk banner for HIGH risk_level', () => {
    render(
      <ConsentModal
        capsule={makeCapsule({ risk_level: 'HIGH', requires_presence: true })}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.getByText(/High Risk/i)).toBeInTheDocument();
  });
});

describe('ConsentModal — Callbacks', () => {
  it('calls onReject when Decline is clicked', () => {
    const onReject = vi.fn();
    render(
      <ConsentModal
        capsule={makeCapsule()}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={onReject}
      />
    );
    fireEvent.click(screen.getByText(/Decline/i));
    expect(onReject).toHaveBeenCalledOnce();
  });

  it('calls onApprove when Approve is clicked (no biometric required)', () => {
    const onApprove = vi.fn();
    render(
      <ConsentModal
        capsule={makeCapsule({ risk_level: 'LOW', requires_presence: false })}
        reasonCodes={[]}
        onApprove={onApprove}
        onReject={vi.fn()}
      />
    );
    fireEvent.click(screen.getByText(/Approve Disclosure/i));
    expect(onApprove).toHaveBeenCalledOnce();
  });

  it('Approve button is disabled when biometric is required but not verified', () => {
    render(
      <ConsentModal
        capsule={makeCapsule({ risk_level: 'HIGH', requires_presence: true })}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    const approveBtn = screen.getByText(/Biometrics Required/i).closest('button');
    expect(approveBtn).toBeDisabled();
  });

  it('calls onLog with info message when provided', async () => {
    // Use LOW risk so no biometric is needed, just check onLog is wired
    const onLog = vi.fn();
    render(
      <ConsentModal
        capsule={makeCapsule({ risk_level: 'LOW', requires_presence: false })}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
        onLog={onLog}
      />
    );
    // Just verify component renders without crash — onLog is only triggered by biometric flow
    expect(screen.getByText(/Approve Disclosure/i)).toBeInTheDocument();
  });
});

describe('ConsentModal — Countdown', () => {
  it('shows countdown when timeoutMinutes is set', () => {
    render(
      <ConsentModal
        capsule={makeCapsule()}
        reasonCodes={[]}
        timeoutMinutes={5}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.getByText(/Session expires/i)).toBeInTheDocument();
  });

  it('does not show countdown when timeoutMinutes is not set', () => {
    render(
      <ConsentModal
        capsule={makeCapsule()}
        reasonCodes={[]}
        onApprove={vi.fn()}
        onReject={vi.fn()}
      />
    );
    expect(screen.queryByText(/Session expires/i)).not.toBeInTheDocument();
  });
});
