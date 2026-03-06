/**
 * G-03b — PolicyEditor component tests
 */

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { PolicyEditor } from '../components/PolicyEditor';
import type { PolicyManifest } from '@mitch/shared-types';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makePolicy(overrides: Partial<PolicyManifest> = {}): PolicyManifest {
  return {
    version: '1.0',
    rules: [
      {
        id: 'rule-liquor-store',
        verifierPattern: 'liquor-store.example.com',
        allowedClaims: ['birthDate'],
        provenClaims: ['age >= 18'],
        priority: 10,
        requiresUserConsent: true,
      }
    ],
    trustedIssuers: [
      {
        did: 'did:example:gov-issuer',
        name: 'Government Issuer',
        credentialTypes: ['AgeCredential'],
      }
    ],
    globalSettings: {
      blockUnknownVerifiers: false,
      requireConsentTimeoutMinutes: 5,
    },
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('PolicyEditor — Rendering', () => {
  it('renders the Governance Settings heading', () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    expect(screen.getByText(/Governance Settings/i)).toBeInTheDocument();
  });

  it('renders trusted issuers from policy', () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    expect(screen.getByText('Government Issuer')).toBeInTheDocument();
    expect(screen.getByText('did:example:gov-issuer')).toBeInTheDocument();
  });

  it('renders credential type badges for each issuer', () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    expect(screen.getByText('AgeCredential')).toBeInTheDocument();
  });

  it('renders Save Changes button', () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    expect(screen.getByText(/Save Changes/i)).toBeInTheDocument();
  });

  it('renders Block Unknown Verifiers toggle', () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    expect(screen.getByText(/Block Unknown Verifiers/i)).toBeInTheDocument();
  });

  it('renders Trusted Issuers section header', () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    expect(screen.getByText(/Trusted Issuers/i)).toBeInTheDocument();
  });
});

describe('PolicyEditor — Save', () => {
  it('calls onSave with current policy when Save Changes is clicked', () => {
    const onSave = vi.fn();
    render(<PolicyEditor policy={makePolicy()} onSave={onSave} />);
    fireEvent.click(screen.getByText(/Save Changes/i));
    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ version: '1.0' }));
  });

  it('shows "Policy Saved" confirmation after save', async () => {
    render(<PolicyEditor policy={makePolicy()} onSave={vi.fn()} />);
    fireEvent.click(screen.getByText(/Save Changes/i));
    expect(screen.getByText(/Policy Saved/i)).toBeInTheDocument();
  });
});

describe('PolicyEditor — Remove Issuer', () => {
  it('removes issuer from list on trash button click', async () => {
    const onSave = vi.fn();
    render(<PolicyEditor policy={makePolicy()} onSave={onSave} />);

    // Trash icon button — find it near the issuer
    const trashBtn = screen.getByText('🗑️').closest('button')!;
    fireEvent.click(trashBtn);

    // After removal, issuer name should no longer be visible
    expect(screen.queryByText('Government Issuer')).not.toBeInTheDocument();
  });
});

describe('PolicyEditor — Multiple Issuers', () => {
  it('renders all trusted issuers when multiple are present', () => {
    const policy = makePolicy({
      trustedIssuers: [
        { did: 'did:example:gov-issuer', name: 'Government Issuer', credentialTypes: ['AgeCredential'] },
        { did: 'did:example:hospital', name: 'St. Mary Hospital', credentialTypes: ['EmploymentCredential'] },
      ]
    });
    render(<PolicyEditor policy={policy} onSave={vi.fn()} />);
    expect(screen.getByText('Government Issuer')).toBeInTheDocument();
    expect(screen.getByText('St. Mary Hospital')).toBeInTheDocument();
  });
});

describe('PolicyEditor — Veto List', () => {
  it('renders veto rules (priority 999)', () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'veto-evil-tracker',
          verifierPattern: 'evil-tracker.com',
          allowedClaims: [],
          provenClaims: [],
          priority: 999,
          requiresUserConsent: false,
        }
      ]
    });
    render(<PolicyEditor policy={policy} onSave={vi.fn()} />);
    expect(screen.getByText('evil-tracker.com')).toBeInTheDocument();
  });

  it('removes veto rule on ✕ click', () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'veto-evil-tracker',
          verifierPattern: 'evil-tracker.com',
          allowedClaims: [],
          provenClaims: [],
          priority: 999,
          requiresUserConsent: false,
        }
      ]
    });
    render(<PolicyEditor policy={policy} onSave={vi.fn()} />);
    const removeBtn = screen.getByText('✕').closest('button')!;
    fireEvent.click(removeBtn);
    expect(screen.queryByText('evil-tracker.com')).not.toBeInTheDocument();
  });
});
