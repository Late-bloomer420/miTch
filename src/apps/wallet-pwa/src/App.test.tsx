/**
 * G-03 — Wallet PWA App Tests
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { PolicyEvaluationResult } from '@askmi/shared-types';

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
  savePolicy: vi.fn().mockResolvedValue(undefined),
  getRecentAuditLogs: vi.fn().mockReturnValue([]),
  handleAction: vi.fn().mockResolvedValue({ success: true, message: 'ok' }),
  resetWallet: vi.fn().mockResolvedValue(undefined),
  addIssuedCredential: vi.fn().mockResolvedValue(undefined),
  fetchAndStoreSdJwtVc: vi.fn().mockResolvedValue('vc-sdjwt-mock-001'),
  // ADOPT-0b: real stored credential path
  getLatestSdJwtVcId: vi.fn().mockResolvedValue('vc-sdjwt-mock-001'),
  presentStoredSdJwtVc: vi.fn().mockResolvedValue({
    vpToken: 'real-vp-token',
    disclosedClaims: { age: 24 },
  }),
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
      clearRegistration: vi.fn().mockResolvedValue(undefined),
      provePresence: vi.fn().mockResolvedValue('proof'),
      provePresenceDetailed: vi.fn().mockResolvedValue({ signature: 'proof-signature' }),
    },
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
  // ADOPT-0b: real credential path — wallet mock already provides getLatestSdJwtVcId + presentStoredSdJwtVc

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

  it('first run shows a framed welcome screen and does NOT auto-fire the passkey ceremony (G-130.1 Task 3)', async () => {
    // The passkey ceremony must be a deliberate, framed user gesture — never an unexplained
    // prompt that auto-fires on mount. An unframed surprise prompt felt "suss / scammy" on
    // real devices; the welcome screen explains the device-bound account BEFORE any biometric.
    const webAuthnServiceMock = vi.mocked(WebAuthnService);
    webAuthnServiceMock.isAvailable.mockResolvedValueOnce(true);
    webAuthnServiceMock.isIdentityRegistered.mockResolvedValueOnce(false);

    render(<App />);

    expect(
      await screen.findByRole('button', { name: /Create my AskMI account/i })
    ).toBeInTheDocument();
    expect(webAuthnServiceMock.registerIdentityKey).not.toHaveBeenCalled();
    expect(screen.queryByText('Age Credential (GovID)')).not.toBeInTheDocument();
  });

  it('first run enrolls only after the explicit Create-account gesture, then lands in the wallet — one ceremony', async () => {
    // The enrollment ceremony already verifies the user (userVerification:required), so the
    // explicit gesture IS the single biometric — no second unlock of the same passkey after it.
    const webAuthnServiceMock = vi.mocked(WebAuthnService);
    webAuthnServiceMock.isAvailable.mockResolvedValueOnce(true);
    webAuthnServiceMock.isIdentityRegistered.mockResolvedValueOnce(false);

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /Create my AskMI account/i }));

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

  it('Reset Wallet wipes the vault and unlinks the device passkey (explicit escape hatch)', async () => {
    const webAuthnServiceMock = vi.mocked(WebAuthnService);
    webAuthnServiceMock.isAvailable.mockResolvedValueOnce(true);
    webAuthnServiceMock.isIdentityRegistered.mockResolvedValueOnce(true); // returning → locked screen
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    render(<App />);

    await screen.findByText('Wallet Locked');
    fireEvent.click(screen.getByRole('button', { name: /Reset Wallet/i }));

    await waitFor(() => {
      expect(walletServiceMockState.resetWallet).toHaveBeenCalledOnce();
      expect(webAuthnServiceMock.clearRegistration).toHaveBeenCalledOnce();
    });
  });

  it('Reset Wallet does nothing if the user cancels the confirmation', async () => {
    const webAuthnServiceMock = vi.mocked(WebAuthnService);
    webAuthnServiceMock.isAvailable.mockResolvedValueOnce(true);
    webAuthnServiceMock.isIdentityRegistered.mockResolvedValueOnce(true);
    vi.spyOn(window, 'confirm').mockReturnValue(false);

    render(<App />);

    await screen.findByText('Wallet Locked');
    fireEvent.click(screen.getByRole('button', { name: /Reset Wallet/i }));

    expect(walletServiceMockState.resetWallet).not.toHaveBeenCalled();
    expect(webAuthnServiceMock.clearRegistration).not.toHaveBeenCalled();
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

  it('always shows the data-flow section, with no show/hide toggle (G-140 Gap D)', async () => {
    render(<App />);
    await screen.findByText('Age Credential (GovID)'); // main authenticated view

    // Panel is permanent through the trace summary tab, but no longer expands by default
    // into a full extra dashboard below the consent view.
    fireEvent.click(screen.getByRole('button', { name: /3 Data flow/i }));
    expect(screen.getByText('Noch keine Transaktionen')).toBeInTheDocument();
    // The old toggle is gone:
    expect(screen.queryByText('Datenflüsse anzeigen')).not.toBeInTheDocument();
    expect(screen.queryByText('Datenflüsse ausblenden')).not.toBeInTheDocument();
  });

  // G-130.1 Task 2 — Get / Refresh Credential UI ------------------------------

  it('shows an empty-state "Get my credential" CTA when the wallet has no credentials', async () => {
    // After passkey onboarding a fresh wallet is empty; the user needs a clear way to
    // acquire their first credential instead of staring at a blank card area.
    walletServiceMockState.getCredentials.mockResolvedValueOnce([]);

    render(<App />);

    expect(
      await screen.findByRole('button', { name: /Get my credential/i })
    ).toBeInTheDocument();
  });

  it('hides the empty-state and shows a Refresh control once credentials exist, and Refresh re-syncs from the vault', async () => {
    // Default mock returns one Age Credential → wallet is non-empty.
    render(<App />);

    expect(await screen.findByText('Age Credential (GovID)')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Get my credential/i })).not.toBeInTheDocument();

    const refreshBtn = screen.getByRole('button', { name: /Refresh/i });
    const before = walletServiceMockState.getCredentials.mock.calls.length;
    fireEvent.click(refreshBtn);

    await waitFor(() => {
      expect(walletServiceMockState.getCredentials.mock.calls.length).toBeGreaterThan(before);
    });
  });

  it('empty-state "Get my credential" fetches a credential from the issuer (OID4VCI) and stores it', async () => {
    // Only the initial load needs to be empty (so the CTA renders); the post-fetch reload
    // can fall back to the default mock. Using ...Once avoids leaking an override into later tests.
    walletServiceMockState.getCredentials.mockResolvedValueOnce([]);

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /Get my credential/i }));

    await waitFor(() => {
      // ADOPT-0a: handler now delegates to fetchAndStoreSdJwtVc (holder PoP + raw SD-JWT VC storage)
      expect(walletServiceMockState.fetchAndStoreSdJwtVc).toHaveBeenCalled();
    });
  });

  // ── Wallet Shell UX polish: scenario launcher + framed trace (presentation only) ──

  it('groups all four scenarios in a single scenario-launcher region', async () => {
    // The four demo scenarios were split — Prove Age at the top, the other three buried
    // at the bottom past every trace panel. They must read as one launcher.
    render(<App />);
    await screen.findByText('Age Credential (GovID)');

    const launcher = screen.getByTestId('scenario-launcher');
    expect(launcher).toContainElement(document.getElementById('btn-liquor-store'));
    expect(launcher).toContainElement(document.getElementById('btn-doctor-login'));
    expect(launcher).toContainElement(document.getElementById('btn-ehds-er'));
    expect(launcher).toContainElement(document.getElementById('btn-pharmacy'));
  });

  it('marks a scenario as active (aria-current) once it is selected', async () => {
    // Bootstrap the mocks so clicking the scenario runs cleanly (no unhandled verdict throw);
    // the assertion is purely about the synchronous active-selection marking.
    await bootstrapFetchMocks('PROMPT');
    render(<App />);
    await screen.findByText('Age Credential (GovID)');

    const doctor = document.getElementById('btn-doctor-login')!;
    expect(doctor).not.toHaveAttribute('aria-current');

    fireEvent.click(doctor);

    expect(document.getElementById('btn-doctor-login')).toHaveAttribute('aria-current', 'true');
  });

  it.each([
    [
      'btn-liquor-store',
      expect.objectContaining({
        verifierId: expect.stringContaining('verifier-liquor-store'),
        requestedClaims: [],
        requestedProvenClaims: ['age >= 18'],
      }),
    ],
    [
      'btn-doctor-login',
      expect.objectContaining({
        verifierId: 'med-portal-login',
        origin: 'https://portal.st-mary.med',
        requirements: expect.arrayContaining([
          expect.objectContaining({
            credentialType: 'AgeCredential',
            requestedClaims: [],
            requestedProvenClaims: ['age >= 18'],
          }),
          expect.objectContaining({
            credentialType: 'EmploymentCredential',
            requestedClaims: ['role', 'licenseId'],
            requestedProvenClaims: [],
          }),
        ]),
      }),
    ],
    [
      'btn-ehds-er',
      expect.objectContaining({
        verifierId: 'hospital-madrid-er-1',
        origin: 'https://er.madrid.health',
        requirements: [
          expect.objectContaining({
            credentialType: 'PatientSummary',
            requestedClaims: ['bloodGroup', 'allergies'],
            requestedProvenClaims: [],
          }),
        ],
      }),
    ],
    [
      'btn-pharmacy',
      expect.objectContaining({
        verifierId: 'pharmacy-berlin-center',
        origin: 'https://pharmacy.berlin.health',
        requirements: [
          expect.objectContaining({
            credentialType: 'Prescription',
            requestedClaims: ['medication', 'dosageInstruction'],
            requestedProvenClaims: [],
          }),
        ],
      }),
    ],
  ])('keeps %s wired to the same wallet evaluation request', async (buttonId, expectedRequest) => {
    await bootstrapFetchMocks('PROMPT');
    render(<App />);
    await screen.findByText('Age Credential (GovID)');

    fireEvent.click(document.getElementById(buttonId)!);

    await waitFor(() => expect(walletServiceMockState.evaluateRequest).toHaveBeenCalledOnce());
    expect(walletServiceMockState.evaluateRequest).toHaveBeenCalledWith(
      expectedRequest,
      expect.objectContaining({ userDID: 'did:example:wallet-user' })
    );
    expect(document.getElementById(buttonId)).toHaveAttribute('aria-current', 'true');
  });

  it('frames consent, compliance and data-flow as one "What just happened" trace section', async () => {
    render(<App />);
    await screen.findByText('Age Credential (GovID)');

    const trace = screen.getByTestId('trace-summary');
    expect(within(trace).getByText(/what just happened/i)).toBeInTheDocument();
    expect(within(trace).getAllByTestId('trace-step')).toHaveLength(3);
    expect(within(trace).queryByText('Consent Manager')).not.toBeInTheDocument();

    fireEvent.click(within(trace).getByRole('button', { name: /1 Consent/i }));

    expect(within(trace).getByRole('button', { name: /1 Consent/i })).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(within(trace).getByText('Consent Manager')).toBeInTheDocument();

    fireEvent.click(within(trace).getByRole('button', { name: /3 Data flow/i }));

    expect(trace).toContainElement(document.getElementById('dataflow-section'));
  });

  it('adds one app-scoped session ID to the standalone verifier presentation', async () => {
    await bootstrapFetchMocks('ALLOW');
    walletServiceMockState.generatePresentation.mockResolvedValue({
      encryptedVp: 'encrypted-presentation',
      auditLog: [],
    });
    render(<App />);
    await screen.findByText('Age Credential (GovID)');

    fireEvent.click(document.getElementById('btn-liquor-store')!);

    await waitFor(() => {
      const presentationCall = vi
        .mocked(fetch)
        .mock.calls.find(([input]) => String(input).endsWith('/present'));
      expect(presentationCall).toBeDefined();
      expect(new Headers(presentationCall?.[1]?.headers).get('X-AskMI-Session-Id')).toMatch(
        /^[0-9a-f-]{36}$/
      );
    });
  });

  it('persists a SUCCESS consent receipt after OID4VP approve', async () => {
    await bootstrapFetchMocks('ALLOW');
    window.history.replaceState(
      {},
      '',
      '/?endpoint=https://verifier.test&scenario=liquor-store&verifier=did:askmi:verifier-liquor-store&sessionId=flow-session-123'
    );

    render(<App />);

    const acceptButton = await screen.findByRole('button', { name: /Accept & Prove/i });
    await waitFor(() => expect(acceptButton).not.toBeDisabled());
    fireEvent.click(acceptButton);
    fireEvent.click(screen.getByRole('button', { name: /1 Consent/i }));

    await screen.findByText('SUCCESS', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);

    const flowCalls = vi.mocked(fetch).mock.calls.filter(([input]) =>
      /notify-scan|authorize|direct_post/.test(String(input))
    );
    expect(flowCalls).toHaveLength(3);
    for (const [, init] of flowCalls) {
      expect(new Headers(init?.headers).get('X-AskMI-Session-Id')).toBe('flow-session-123');
    }
  });

  it('persists a DENIED receipt when the verifier rejects the presentation', async () => {
    await bootstrapFetchMocks('ALLOW');
    window.history.replaceState(
      {},
      '',
      '/?endpoint=https://verifier.test&scenario=liquor-store&verifier=did:askmi:verifier-liquor-store&sessionId=flow-session-123'
    );
    // ADOPT-0b: real credential path — wallet mock provides presentStoredSdJwtVc
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
    fireEvent.click(screen.getByRole('button', { name: /1 Consent/i }));

    await screen.findByText('DENIED', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);
  });
});
