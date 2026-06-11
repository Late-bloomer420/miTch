/**
 * G-03 — Wallet PWA App Tests
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { PolicyEvaluationResult } from '@askmi/shared-types';

const buildSDJWTPresentationMock = vi.hoisted(() => vi.fn());
const walletServiceMockState = vi.hoisted(() => ({
  initialize: vi.fn().mockResolvedValue(undefined),
  getPolicy: vi
    .fn()
    .mockReturnValue({ version: 'test', rules: [], trustedIssuers: [], globalSettings: {} }),
  getCredentials: vi.fn().mockResolvedValue([
    {
      id: 'vc-age-789',
      issuer: 'did:example:gov-issuer',
      type: ['VerifiableCredential', 'AgeCredential'],
      issuedAt: new Date().toISOString(),
      claims: ['birthDate', 'age'],
    },
  ]),
  evaluateRequest: vi.fn(),
  generatePresentation: vi.fn(),
  recordIdentityFirewallEvents: vi.fn().mockResolvedValue([]),
  exportAuditReport: vi.fn().mockResolvedValue({
    version: '1',
    exportedAt: '2026-05-21T10:00:00.000Z',
    owner: 'did:example:wallet-user',
    entries: [],
    chainIntegrity: { valid: true },
    reportHash: 'hash',
  }),
  syncAuditToL2: vi.fn().mockResolvedValue({}),
  verifyAuditChain: vi.fn().mockResolvedValue({ valid: true }),
  savePolicy: vi.fn(),
  getRecentAuditLogs: vi.fn().mockReturnValue([]),
  handleAction: vi.fn().mockResolvedValue({ success: true, message: 'ok' }),
}));

vi.mock('./components/SecureZone', () => ({
  SecureZone: ({
    children,
    className,
    style,
  }: {
    children: React.ReactNode;
    className?: string;
    style?: React.CSSProperties;
  }) => (
    <div className={className} style={style}>
      {children}
    </div>
  ),
}));

vi.mock('@askmi/shared-crypto', async () => {
  const actual =
    await vi.importActual<typeof import('@askmi/shared-crypto')>('@askmi/shared-crypto');
  return {
    ...actual,
    WebAuthnService: {
      isAvailable: vi.fn().mockResolvedValue(false),
      isRegistered: vi.fn().mockResolvedValue(false),
      isIdentityRegistered: vi.fn().mockResolvedValue(false),
      registerPasskey: vi.fn().mockResolvedValue(undefined),
      registerIdentityKey: vi.fn().mockResolvedValue(undefined),
      provePresence: vi.fn().mockResolvedValue('proof'),
      provePresenceDetailed: vi.fn().mockResolvedValue({ signature: 'proof-signature' }),
    },
  };
});

vi.mock('@askmi/oid4vp', async () => {
  const actual = await vi.importActual<typeof import('@askmi/oid4vp')>('@askmi/oid4vp');
  return {
    ...actual,
    buildSDJWTPresentation: buildSDJWTPresentationMock,
  };
});

vi.mock('./services/WalletService', () => {
  return {
    WalletService: class {
      constructor() {
        return walletServiceMockState as never;
      }
    },
  };
});

import App from './App';
import { WebAuthnService } from '@askmi/shared-crypto';

function makePromptResult(verdict: PolicyEvaluationResult['verdict']): PolicyEvaluationResult {
  return {
    verdict,
    reasonCodes: verdict === 'PROMPT' ? ['CONSENT_REQUIRED'] : [],
    decisionCapsule: {
      decision_id: 'decision-001',
      verdict,
      request_hash: 'req-hash',
      policy_hash: 'policy-hash',
      verifier_did: 'did:askmi:verifier-liquor-store',
      authorized_requirements: [
        {
          credential_type: 'AgeCredential',
          allowed_claims: ['age'],
          proven_claims: ['age >= 18'],
          selected_credential_id: 'vc-1',
          issuer_trust_refs: [],
          requested_claims: ['age'],
        },
      ],
      risk_level: 'LOW',
      requires_presence: false,
      expires_at: '2026-05-21T10:05:00.000Z',
      audience: 'wallet-pwa',
      issued_at: '2026-05-21T10:00:00.000Z',
    },
  };
}

async function bootstrapFetchMocks(verdict: PolicyEvaluationResult['verdict']) {
  walletServiceMockState.evaluateRequest.mockResolvedValue(makePromptResult(verdict));
  buildSDJWTPresentationMock.mockResolvedValue({
    vpTokenString: 'vp-token',
    presentationSubmission: { id: 'ps-1', definition_id: 'def-1', descriptor_map: [] },
    disclosedClaims: { age: 24 },
  });
  vi.spyOn(crypto.subtle, 'generateKey').mockResolvedValue({
    privateKey: {} as CryptoKey,
    publicKey: {} as CryptoKey,
  } as CryptoKeyPair);
  vi.spyOn(crypto.subtle, 'exportKey').mockResolvedValue({ kty: 'EC', crv: 'P-256' } as JsonWebKey);

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/authorize')) {
        return new Response(
          JSON.stringify({
            authRequest: {
              response_type: 'vp_token',
              client_id: 'did:askmi:verifier-liquor-store',
              redirect_uri: 'https://verifier.test/direct_post',
              nonce: 'nonce-1',
              presentation_definition: {
                id: 'pd-1',
                purpose: 'Age verification',
                input_descriptors: [
                  { id: 'descriptor-1', constraints: { fields: [{ path: ['$.age'] }] } },
                ],
              },
              state: 'state-1',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (url.includes('/direct_post')) {
        return new Response(JSON.stringify({ ok: true, disclosedClaims: { age: 24 } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as unknown as typeof fetch
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState({}, '', '/');
});

describe('G-03 — Wallet App', () => {
  it('renders the wallet title', () => {
    render(<App />);
    expect(screen.getByText('AskMI')).toBeInTheDocument();
  });

  it('renders credential card with Age Credential', async () => {
    render(<App />);
    expect(await screen.findByText('Age Credential (GovID)')).toBeInTheDocument();
  });

  it('enrolls on first run and lands straight in the wallet — a single biometric ceremony', async () => {
    // Model A UX: the registration ceremony already verifies the user (userVerification:required),
    // so first run must NOT immediately demand a second unlock of the same passkey.
    const webAuthnServiceMock = vi.mocked(WebAuthnService);
    webAuthnServiceMock.isAvailable.mockResolvedValueOnce(true);
    webAuthnServiceMock.isIdentityRegistered.mockResolvedValueOnce(false);

    render(<App />);

    // Straight into the wallet after enrollment — no second "Wallet Locked" gate.
    expect(await screen.findByText('Age Credential (GovID)')).toBeInTheDocument();
    expect(webAuthnServiceMock.registerIdentityKey).toHaveBeenCalledOnce();
    expect(webAuthnServiceMock.provePresence).not.toHaveBeenCalled();
    expect(screen.queryByText('Wallet Locked')).not.toBeInTheDocument();
  });

  it('returning device with an existing identity is locked until a single unlock', async () => {
    // Model A guarantee: returning device reuses its identity (no re-enroll) and is gated
    // behind exactly one unlock ceremony before any credential is shown.
    const webAuthnServiceMock = vi.mocked(WebAuthnService);
    webAuthnServiceMock.isAvailable.mockResolvedValueOnce(true);
    webAuthnServiceMock.isIdentityRegistered.mockResolvedValueOnce(true);

    render(<App />);

    expect(await screen.findByText('Wallet Locked')).toBeInTheDocument();
    expect(webAuthnServiceMock.registerIdentityKey).not.toHaveBeenCalled();
    expect(webAuthnServiceMock.registerPasskey).not.toHaveBeenCalled();
    expect(screen.queryByText('Age Credential (GovID)')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Unlock with Biometrics/i }));

    expect(await screen.findByText('Age Credential (GovID)')).toBeInTheDocument();
    expect(webAuthnServiceMock.provePresence).toHaveBeenCalledWith('AskMI-wallet-unlock');
  });

  it('renders the primary action button', () => {
    render(<App />);
    expect(document.getElementById('btn-liquor-store')).not.toBeNull();
  });

  it('renders demo section', () => {
    render(<App />);
    const demoSection =
      screen.queryByText('🚀 Advanced Feature Demos') || screen.queryByText('🚀 Demo Scenarios');
    expect(demoSection).not.toBeNull();
  });

  it('renders Doctor Login, EHDS, Pharmacy and Age Check demo button IDs', () => {
    render(<App />);
    expect(document.getElementById('btn-doctor-login')).not.toBeNull();
    expect(document.getElementById('btn-pharmacy')).not.toBeNull();
    expect(document.getElementById('btn-ehds-er')).not.toBeNull();
    expect(document.getElementById('btn-liquor-store')).not.toBeNull();
  });

  it('persists a SUCCESS consent receipt after OID4VP approve', async () => {
    await bootstrapFetchMocks('ALLOW');
    window.history.replaceState(
      {},
      '',
      '/?endpoint=https://verifier.test&scenario=liquor-store&verifier=did:askmi:verifier-liquor-store'
    );

    render(<App />);

    const acceptButton = await screen.findByRole('button', { name: /Accept & Prove/i });
    await waitFor(() => expect(acceptButton).not.toBeDisabled());
    fireEvent.click(acceptButton);

    await screen.findByText('SUCCESS', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);
  });

  it('persists a DENIED receipt when the verifier rejects the presentation', async () => {
    await bootstrapFetchMocks('ALLOW');
    window.history.replaceState(
      {},
      '',
      '/?endpoint=https://verifier.test&scenario=liquor-store&verifier=did:askmi:verifier-liquor-store'
    );
    buildSDJWTPresentationMock.mockResolvedValue({
      vpTokenString: 'vp-token',
      presentationSubmission: { id: 'ps-1', definition_id: 'def-1', descriptor_map: [] },
      disclosedClaims: { age: 24 },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/authorize')) {
          return new Response(
            JSON.stringify({
              authRequest: {
                response_type: 'vp_token',
                client_id: 'did:askmi:verifier-liquor-store',
                redirect_uri: 'https://verifier.test/direct_post',
                nonce: 'nonce-1',
                presentation_definition: {
                  id: 'pd-1',
                  purpose: 'Age verification',
                  input_descriptors: [
                    { id: 'descriptor-1', constraints: { fields: [{ path: ['$.age'] }] } },
                  ],
                },
                state: 'state-1',
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }
        if (url.includes('/direct_post')) {
          return new Response(JSON.stringify({ ok: false, error: 'rejected' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
      }) as unknown as typeof fetch
    );

    render(<App />);

    const acceptButton = await screen.findByRole('button', { name: /Accept & Prove/i });
    await waitFor(() => expect(acceptButton).not.toBeDisabled());
    fireEvent.click(acceptButton);

    await screen.findByText('DENIED', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);
  });
});
