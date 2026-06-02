import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';
import { WalletService } from '@mitch/wallet-core';
import type { PolicyEvaluationResult } from '@mitch/shared-types';

// Mock @mitch/oid4vp
vi.mock('@mitch/oid4vp', () => {
    return {
        buildSDJWTPresentation: vi.fn().mockResolvedValue({
            vpTokenString: 'mock-vp-token',
            presentationSubmission: { id: 'pd-1', definition_id: 'pd-1', descriptor_map: [] },
            disclosedClaims: { age: 24 }
        }),
        buildSessionCleanup: vi.fn().mockReturnValue({
            consentReceipt: { 
                id: 'consent-123', 
                verifier: 'did:mitch:verifier-liquor-store',
                claimsShared: ['age'], 
                purpose: 'Age Verification', 
                timestamp: new Date().toISOString() 
            },
            auditEntry: { outcome: 'SUCCESS' }
        }),
        SCENARIO_VCT: { 'liquor-store': 'https://vct.test' }
    };
});

// Properly structured Mock Class for Vitest constructor support
// Using a function factory that returns a pre-configured instance
const createMockWallet = () => ({
    initialize: vi.fn().mockResolvedValue(undefined),
    getCredentials: vi.fn().mockResolvedValue([
        {
        id: 'vc-age-7',
        type: ['AgeCredential'],
        issuer: 'did:example:gov-issuer',
        issuedAt: new Date().toISOString(),
        },
    ]),
    getPolicy: vi.fn().mockReturnValue({}),
    evaluateRequest: vi.fn().mockResolvedValue({
        verdict: 'ALLOW',
        decisionCapsule: {
        decision_id: 'decision-001',
        verifier_did: 'did:mitch:verifier-liquor-store',
        },
        reasonCodes: ['✋ Explicit consent required'],
    }),
    generatePresentation: vi.fn().mockResolvedValue({
        encryptedVp: 'fake-vp-token',
        auditLog: ['✅ Generating SD-JWT VP...'],
    }),
    getRecentAuditLogs: vi.fn().mockReturnValue([]),
    recordIdentityFirewallEvents: vi.fn().mockResolvedValue([]),
    savePolicy: vi.fn(),
});

let activeMockWallet = createMockWallet();

vi.mock('@mitch/wallet-core', () => {
    return {
        WalletService: {
            // Static factory mock
            createBrowserWallet: vi.fn().mockImplementation(() => Promise.resolve(activeMockWallet))
        }
    };
});

async function bootstrapFetchMocks(verdict: PolicyEvaluationResult['verdict']) {
  // Mock window.fetch
  global.fetch = vi.fn().mockImplementation((url) => {
    if (url.includes('/authorize')) {
      return Promise.resolve({
        ok: true,
        json: async () => ({
          authRequest: {
            state: 'state-123',
            redirect_uri: 'https://verifier.test/direct_post',
            presentation_definition: { id: 'pd-1', input_descriptors: [] },
          },
        }),
      });
    }
    if (url.includes('/notify-scan') || url.includes('/direct_post')) {
      return Promise.resolve({ ok: true, json: async () => ({ ok: true }) });
    }
    return Promise.resolve({ ok: false });
  });

  // Update active mock for the current test
  activeMockWallet.evaluateRequest.mockResolvedValue({
    verdict,
    decisionCapsule: {
      decision_id: 'decision-001',
      verifier_did: 'did:mitch:verifier-liquor-store',
    },
    reasonCodes: ['✋ Explicit consent required'],
  });
}

describe('G-03 — Wallet App', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    activeMockWallet = createMockWallet();
    sessionStorage.clear();
    // Reset location
    window.history.replaceState({}, '', '/');
  });

  it('renders the wallet title', async () => {
    render(<App />);
    // Match part of the logo text
    expect(await screen.findByText(/mi/i)).toBeInTheDocument();
  });

  it('renders credential card with Age Credential', async () => {
    render(<App />);
    expect(await screen.findByText(/Government ID/i)).toBeInTheDocument();
  });

  it('renders the primary action button', async () => {
    render(<App />);
    expect(await screen.findByRole('button', { name: /Age Check/i })).toBeInTheDocument();
  });

  it('renders demo section', async () => {
    render(<App />);
    const demoHeader = await screen.findByText(/Quick Actions/i);
    expect(demoHeader).toBeInTheDocument();
  });

  it('renders Doctor Login, EHDS, Pharmacy and Age Check demo button IDs', async () => {
    render(<App />);
    expect(await screen.findByText(/Doctor Login/i)).toBeInTheDocument();
    expect(await screen.findByText(/Pharmacy/i)).toBeInTheDocument();
    expect(await screen.findByText(/EHDS ER/i)).toBeInTheDocument();
  });

  it('persists a SUCCESS consent receipt after OID4VP approve', async () => {
    await bootstrapFetchMocks('PROMPT');
    window.history.replaceState(
      {},
      '',
      '/?endpoint=https://verifier.test&scenario=liquor-store&verifier=did:mitch:verifier-liquor-store'
    );

    render(<App />);

    const acceptButton = await screen.findByRole('button', { name: /Approve/i });
    await waitFor(() => expect(acceptButton).not.toBeDisabled());
    fireEvent.click(acceptButton);

    // Should find the status in the history
    await screen.findByText('SUCCESS', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);
  });

  it('persists a DENIED receipt when the verifier rejects the presentation', async () => {
    await bootstrapFetchMocks('PROMPT');
    window.history.replaceState(
      {},
      '',
      '/?endpoint=https://verifier.test&scenario=liquor-store&verifier=did:mitch:verifier-liquor-store'
    );

    // Mock verifier rejection
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/authorize')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            authRequest: {
              state: 'state-123',
              redirect_uri: 'https://verifier.test/direct_post',
              presentation_definition: { id: 'pd-1', input_descriptors: [] },
            },
          }),
        });
      }
      if (url.includes('/direct_post')) {
        return Promise.resolve({
          ok: false,
          status: 403,
          json: async () => ({ ok: false, error: 'rejected' }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => ({}) });
    });

    render(<App />);

    const acceptButton = await screen.findByRole('button', { name: /Approve/i });
    await waitFor(() => expect(acceptButton).not.toBeDisabled());
    fireEvent.click(acceptButton);

    await screen.findByText('DENIED', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);
  });
});
