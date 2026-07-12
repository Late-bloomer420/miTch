/**
 * G-03 — Wallet PWA App Tests
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
  resetWallet: vi.fn().mockResolvedValue(undefined),
  deleteCredential: vi.fn().mockResolvedValue(true),
  requestDataErasure: vi
    .fn()
    .mockResolvedValue({ success: true, message: 'Erasure request sent.' }),
  reportRelyingParty: vi.fn().mockResolvedValue({ success: true, message: 'Report submitted.' }),
  parseDeepLinkRequest: vi.fn(),
  seedMalicious: vi.fn().mockResolvedValue(undefined),
  corruptCredential: vi.fn().mockResolvedValue(undefined),
  evaluateAgainstExplosion: vi.fn(),
  getRawCredentialDocument: vi.fn().mockResolvedValue({ envelope: 'encrypted' }),
  addIssuedCredential: vi.fn().mockResolvedValue(undefined),
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

async function openWalletPage(
  name:
    | 'Credentials'
    | 'Requests'
    | 'Trace'
    | 'Sovereignty'
    | 'Documents'
    | 'Proximity'
    | 'Renderer'
    | 'Audit'
    | 'Settings'
    | 'Tools'
) {
  await screen.findByText('Age Credential (GovID)');
  fireEvent.click(screen.getByRole('button', { name }));
}

beforeEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState({}, '', '/');
  walletServiceMockState.getCredentials.mockResolvedValue([
    {
      id: 'vc-age-789',
      issuer: 'did:example:gov-issuer',
      type: ['VerifiableCredential', 'AgeCredential'],
      issuedAt: new Date().toISOString(),
      claims: ['birthDate', 'age'],
    },
  ]);
  walletServiceMockState.evaluateRequest.mockResolvedValue(makePromptResult('ALLOW'));
  walletServiceMockState.getRecentAuditLogs.mockReturnValue([]);
  walletServiceMockState.deleteCredential.mockResolvedValue(true);
  walletServiceMockState.requestDataErasure.mockResolvedValue({
    success: true,
    message: 'Erasure request sent.',
  });
  walletServiceMockState.reportRelyingParty.mockResolvedValue({
    success: true,
    message: 'Report submitted.',
  });
  walletServiceMockState.parseDeepLinkRequest.mockResolvedValue({
    verifierId: 'did:askmi:verifier-liquor-store',
    nonce: 'dev-nonce-001',
    requirements: [
      {
        credentialType: 'VerifiableCredential',
        requestedClaims: ['age'],
        requestedProvenClaims: ['age >= 18'],
      },
    ],
  });
  walletServiceMockState.seedMalicious.mockResolvedValue(undefined);
  walletServiceMockState.corruptCredential.mockResolvedValue(undefined);
  walletServiceMockState.evaluateAgainstExplosion.mockResolvedValue(makePromptResult('ALLOW'));
  walletServiceMockState.getRawCredentialDocument.mockResolvedValue({ envelope: 'encrypted' });
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

  it('uses localized medical claim labels on visible credential cards', async () => {
    vi.spyOn(window.navigator, 'language', 'get').mockReturnValue('de-DE');
    walletServiceMockState.getCredentials.mockResolvedValue([
      {
        id: 'vc-patient-summary',
        issuer: 'did:example:ehds-issuer',
        type: ['VerifiableCredential', 'PatientSummary'],
        issuedAt: new Date().toISOString(),
        claims: ['bloodGroup', 'allergies', 'activeProblems', 'emergencyContacts'],
      },
    ]);

    render(<App />);

    expect(await screen.findByText('EHDS Patient Health Summary')).toBeInTheDocument();
    expect(screen.getByText(/Blutgruppe/)).toBeInTheDocument();
    expect(screen.getByText(/Allergien/)).toBeInTheDocument();
  });

  it('deletes a single credential from the visible wallet card', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    render(<App />);

    await screen.findByText('Age Credential (GovID)');
    fireEvent.click(screen.getByRole('button', { name: /Delete Age Credential/i }));

    await waitFor(() => {
      expect(walletServiceMockState.deleteCredential).toHaveBeenCalledWith('vc-age-789');
    });
    expect(walletServiceMockState.getCredentials).toHaveBeenCalledTimes(2);
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

  it('renders the primary action button on the Requests page', async () => {
    render(<App />);
    await openWalletPage('Requests');
    expect(document.getElementById('btn-liquor-store')).not.toBeNull();
  });

  it('renders request section as its own wallet page', async () => {
    render(<App />);
    await openWalletPage('Requests');
    const demoSection =
      screen.queryByText('🚀 Advanced Feature Demos') || screen.queryByText('Verifier Requests');
    expect(demoSection).not.toBeNull();
  });

  it('renders Doctor Login, EHDS, Pharmacy and Age Check request button IDs', async () => {
    render(<App />);
    await openWalletPage('Requests');
    expect(document.getElementById('btn-doctor-login')).not.toBeNull();
    expect(document.getElementById('btn-pharmacy')).not.toBeNull();
    expect(document.getElementById('btn-ehds-er')).not.toBeNull();
    expect(document.getElementById('btn-liquor-store')).not.toBeNull();
  });

  it('always shows the data-flow section, with no show/hide toggle (G-140 Gap D)', async () => {
    render(<App />);
    await openWalletPage('Trace');

    // Panel is permanent on the Trace page, but no longer expands by default into a
    // full extra dashboard below the credential view.
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
    const vcPayload = btoa(JSON.stringify({ vc: { credentialSubject: { age: 21 } } }));
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ credential: `h.${vcPayload}.s` }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: /Get my credential/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/credential'),
        expect.objectContaining({ method: 'POST' })
      );
      expect(walletServiceMockState.addIssuedCredential).toHaveBeenCalled();
    });
  });

  // ── Wallet Shell UX polish: scenario launcher + framed trace (presentation only) ──

  it('groups all four scenarios in a single scenario-launcher region', async () => {
    // The four verifier request examples belong on one dedicated page, not mixed through
    // the wallet, trace, audit, or settings pages.
    render(<App />);
    await openWalletPage('Requests');

    const launcher = screen.getByTestId('scenario-launcher');
    expect(launcher).toContainElement(document.getElementById('btn-liquor-store'));
    expect(launcher).toContainElement(document.getElementById('btn-doctor-login'));
    expect(launcher).toContainElement(document.getElementById('btn-ehds-er'));
    expect(launcher).toContainElement(document.getElementById('btn-pharmacy'));
  });

  it('renders direct wallet page navigation', async () => {
    render(<App />);
    await screen.findByText('Age Credential (GovID)');

    const nav = screen.getByRole('navigation', { name: /wallet sections/i });
    expect(within(nav).getByRole('button', { name: 'Credentials' })).toHaveAttribute(
      'aria-current',
      'page'
    );

    fireEvent.click(within(nav).getByRole('button', { name: 'Requests' }));
    expect(within(nav).getByRole('button', { name: 'Requests' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByTestId('scenario-launcher')).toBeInTheDocument();

    fireEvent.click(within(nav).getByRole('button', { name: 'Trace' }));
    expect(within(nav).getByRole('button', { name: 'Trace' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByTestId('trace-summary')).toBeInTheDocument();

    fireEvent.click(within(nav).getByRole('button', { name: 'Sovereignty' }));
    expect(within(nav).getByRole('button', { name: 'Sovereignty' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getAllByRole('heading', { name: 'Sovereignty Center' }).length).toBeGreaterThan(
      0
    );

    fireEvent.click(within(nav).getByRole('button', { name: 'Documents' }));
    expect(within(nav).getByRole('button', { name: 'Documents' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByRole('heading', { name: 'Documents' })).toBeInTheDocument();
    expect(screen.getByText(/Document Signing/)).toBeInTheDocument();

    fireEvent.click(within(nav).getByRole('button', { name: 'Proximity' }));
    expect(within(nav).getByRole('button', { name: 'Proximity' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByRole('heading', { name: 'Proximity' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start proximity preview' })).toBeInTheDocument();

    fireEvent.click(within(nav).getByRole('button', { name: 'Renderer' }));
    expect(within(nav).getByRole('button', { name: 'Renderer' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByRole('heading', { name: 'Credential Renderer' })).toBeInTheDocument();

    fireEvent.click(within(nav).getByRole('button', { name: 'Tools' }));
    expect(within(nav).getByRole('button', { name: 'Tools' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByRole('heading', { name: 'Tools' })).toBeInTheDocument();
    expect(within(nav).queryByRole('button', { name: 'Dev' })).not.toBeInTheDocument();
  });

  it('combines advanced tools and dev workbench on the Tools page', async () => {
    render(<App />);
    await openWalletPage('Tools');

    expect(screen.getByRole('heading', { name: 'Tools' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start guided flow' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'DEV Workbench' })).toBeInTheDocument();
  });

  it('wires the dev deep-link parser from the Tools page', async () => {
    render(<App />);
    await openWalletPage('Tools');

    fireEvent.click(screen.getByRole('button', { name: /Parse \+ evaluate/i }));

    await waitFor(() => {
      expect(walletServiceMockState.parseDeepLinkRequest).toHaveBeenCalledWith(
        expect.stringContaining('mitch://present')
      );
      expect(walletServiceMockState.evaluateRequest).toHaveBeenCalled();
    });
    expect(await screen.findByText(/Parsed did:askmi:verifier-liquor-store/)).toBeInTheDocument();
  });

  it('marks a scenario as active (aria-current) once it is selected', async () => {
    // Bootstrap the mocks so clicking the scenario runs cleanly (no unhandled verdict throw);
    // the assertion is purely about the synchronous active-selection marking.
    await bootstrapFetchMocks('PROMPT');
    render(<App />);
    await openWalletPage('Requests');

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
    await openWalletPage('Requests');

    fireEvent.click(document.getElementById(buttonId)!);

    await waitFor(() => expect(walletServiceMockState.evaluateRequest).toHaveBeenCalledOnce());
    expect(walletServiceMockState.evaluateRequest).toHaveBeenCalledWith(
      expectedRequest,
      expect.objectContaining({ userDID: 'did:example:wallet-user' })
    );
    expect(document.getElementById(buttonId)).toHaveAttribute('aria-current', 'true');
  });

  it('frames requested, allowed and sent evidence as one disclosure trace section', async () => {
    render(<App />);
    await openWalletPage('Trace');

    const trace = screen.getByTestId('trace-summary');
    expect(within(trace).getByText(/disclosure trace/i)).toBeInTheDocument();
    expect(within(trace).getAllByTestId('trace-step')).toHaveLength(3);
    expect(within(trace).queryByText('Consent Manager')).not.toBeInTheDocument();

    fireEvent.click(within(trace).getByRole('button', { name: /1 Requested/i }));

    expect(within(trace).getByRole('button', { name: /1 Requested/i })).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(within(trace).getByText('Consent Manager')).toBeInTheDocument();

    fireEvent.click(within(trace).getByRole('button', { name: /3 Sent/i }));

    expect(trace).toContainElement(document.getElementById('dataflow-section'));
  });

  it('wires data-flow erasure action to the wallet service', async () => {
    walletServiceMockState.getRecentAuditLogs.mockReturnValue([
      {
        id: 'audit-erasure',
        timestamp: '2026-03-15T10:00:00Z',
        action: 'VP_SENT',
        previousHash: '0'.repeat(64),
        currentHash: 'a'.repeat(64),
        metadata: {
          decision_id: 'decision-erasure',
          context: 'PROXIMITY_PRESENTATION',
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_requested: ['age'],
          claims_shared: ['age'],
          erasure_endpoint: 'https://verifier.test/erase',
        },
      },
    ]);

    render(<App />);
    await openWalletPage('Trace');
    fireEvent.click(screen.getByText('Liquor Store'));
    fireEvent.click(screen.getByRole('button', { name: /Löschung anfordern/i }));

    await waitFor(() => {
      expect(walletServiceMockState.requestDataErasure).toHaveBeenCalledWith('decision-erasure');
    });
  });

  it('wires data-flow reporting action to the wallet service', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('Over-requesting observed');
    walletServiceMockState.getRecentAuditLogs.mockReturnValue([
      {
        id: 'audit-report',
        timestamp: '2026-03-15T10:00:00Z',
        action: 'VP_SENT',
        previousHash: '0'.repeat(64),
        currentHash: 'a'.repeat(64),
        metadata: {
          decision_id: 'decision-report',
          context: 'PROXIMITY_PRESENTATION',
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_requested: ['age', 'healthRecord'],
          claims_shared: ['age'],
        },
      },
    ]);

    render(<App />);
    await openWalletPage('Trace');
    fireEvent.click(screen.getByText('Liquor Store'));
    fireEvent.click(screen.getByRole('button', { name: /Melden/i }));

    await waitFor(() => {
      expect(walletServiceMockState.reportRelyingParty).toHaveBeenCalledWith(
        'decision-report',
        'Over-requesting observed'
      );
    });
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
    fireEvent.click(screen.getByRole('button', { name: 'Trace' }));
    fireEvent.click(screen.getByRole('button', { name: /1 Requested/i }));

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
    fireEvent.click(screen.getByRole('button', { name: 'Trace' }));
    fireEvent.click(screen.getByRole('button', { name: /1 Requested/i }));

    await screen.findByText('DENIED', { selector: '.consent-manager-panel__history-pill' });
    expect(screen.getAllByText(/consent-/).length).toBeGreaterThan(0);
  });
});
