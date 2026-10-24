import type { AskMIHandoff } from '../browser/handoff';

/**
 * ADOPT-1.1 minimal session contract types for `@askmi/connect`.
 *
 * Every verifier-side session carries exactly the fields the contract
 * requires — no application-supplied nonce, audience, verifier DID,
 * issuer, claim lists or result values are ever accepted as input.
 */

/** The only registered policy id of the first code slice. */
export type AskMIConnectPolicyId = 'age-liquor-store-v1';

/** Session state machine (ADOPT-1.1). */
export type AskMIConnectSessionStatus =
  | 'pending'
  | 'wallet_opened'
  | 'verified'
  | 'failed'
  | 'expired';

/** Stable error codes (ADOPT-1.1). Raw exception text never leaves the core. */
export type AskMIConnectErrorCode =
  | 'UNKNOWN_POLICY'
  | 'UNKNOWN_SESSION'
  | 'SESSION_EXPIRED'
  | 'SESSION_TERMINAL'
  | 'MALFORMED_PRESENTATION'
  | 'WRONG_AUDIENCE'
  | 'WRONG_NONCE'
  | 'REPLAY_DETECTED'
  | 'UNTRUSTED_ISSUER'
  | 'ISSUER_RESOLUTION_FAILED'
  | 'SIGNATURE_INVALID'
  | 'INSUFFICIENT_CLAIMS'
  | 'POLICY_DENIED'
  | 'SIMULATED_ROUTE_REJECTED'
  | 'INTERNAL_ERROR';

/** A registered policy (ADOPT-1.1). Applications choose by id, nothing else. */
export interface AskMIConnectPolicy {
  readonly id: AskMIConnectPolicyId;
  readonly version: 1;
  readonly purpose: 'Liquor purchase age eligibility';
  readonly profile: 'sd-jwt-vc-age-v1';
  readonly requestedClaims: readonly ['age'];
  readonly requiredClaims: readonly ['age'];
  readonly resultClaim: 'eligible';
}

/**
 * Provenance block of a verified session. Claim NAMES only — never raw
 * credential values, disclosures, holder keys or stable person
 * identifiers.
 */
export interface AskMIConnectProvenance {
  readonly policyId: AskMIConnectPolicyId;
  readonly policyVersion: 1;
  readonly credentialProfile: 'sd-jwt-vc-age-v1';
  readonly claimsShared: readonly string[];
  readonly claimsWithheld: readonly string[];
  readonly correlationId: string;
}

/** Verification summary of a verified session. */
export interface AskMIConnectVerification {
  readonly cryptographic: 'passed';
  readonly issuerTrust: 'passed';
  readonly policy: 'allowed';
  readonly userApproval: 'presentation_received';
}

/** The application result — derived by the policy, never caller-supplied. */
export interface AskMIConnectResult {
  readonly eligible: boolean;
}

/** One verifier-side session. */
export interface AskMIConnectSession {
  readonly sessionId: string;
  readonly status: AskMIConnectSessionStatus;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly audience: string;
  readonly verifierDid: string;
  readonly policyId: AskMIConnectPolicyId;
  readonly policyVersion: 1;
  readonly correlationId: string;
  readonly returnUrl?: string;
  /** Terminal failure code (only when status === 'failed'). */
  readonly errorCode?: AskMIConnectErrorCode;
  /** Present on 'verified' sessions only; claim names only, no values. */
  readonly result?: AskMIConnectResult;
  readonly verification?: AskMIConnectVerification;
  readonly provenance?: AskMIConnectProvenance;
}

/** Only lifecycle fields may change; session bindings remain server-owned. */
export type AskMIConnectSessionUpdate =
  | { status: 'wallet_opened' }
  | { status: 'failed'; errorCode: AskMIConnectErrorCode }
  | {
      status: 'verified';
      result: AskMIConnectResult;
      verification: AskMIConnectVerification;
      provenance: AskMIConnectProvenance;
    };

export interface AskMIConnectSessionUpdateResult {
  /** False means no requested transition was written. Discard the computed result. */
  applied: boolean;
  session: AskMIConnectSession | null;
}

/**
 * Pluggable session storage. get/consume/update must evaluate expiry using the
 * same clock. update MUST atomically check the current state and TTL with the
 * write: terminal states are absorbing, elapsed TTL becomes expired, and a
 * removed record is never recreated. No read-then-unconditional-write fallback.
 * A DB/Redis adapter must enforce these conditions transactionally at commit.
 */
export interface AskMIConnectSessionStore {
  create(session: AskMIConnectSession): Promise<void>;
  get(sessionId: string): Promise<AskMIConnectSession | null>;
  update(
    sessionId: string,
    update: AskMIConnectSessionUpdate
  ): Promise<AskMIConnectSessionUpdateResult>;
  consume(sessionId: string): Promise<AskMIConnectSession | null>;
  deleteExpired(now: Date): Promise<number>;
}

/** Configuration of the Connect kit. All trust anchors are configured here. */
export interface AskMIConnectConfig {
  /** The verifier's own DID — bound into every session and KB audience check. */
  verifierDid: string;
  /** Base URL of the relying party hosting the Connect routes. */
  audienceBaseUrl: string;
  /** Base URL of the wallet for handoff links. */
  walletBaseUrl: string;
  /** Session TTL in milliseconds (default 5 minutes). */
  sessionTtlMs?: number;
  /** Millisecond clock for creation and the default store. Custom stores must use this same source. */
  now?: () => number;
  /** Session store; defaults to a new InMemoryAskMIConnectSessionStore. */
  store?: AskMIConnectSessionStore;
  /**
   * Trust-gated issuer key resolution: returns the issuer's public key for a
   * credential `iss`, or null when the issuer is not trusted. Reject on lookup
   * failure (ISSUER_RESOLUTION_FAILED); the consumed session is terminal and
   * retry requires a fresh session/nonce.
   * Fail-closed default: resolve nothing (every presentation fails as
   * UNTRUSTED_ISSUER) until a real trust-list/JWKS resolver is injected.
   */
  issuerKeyResolver?: (iss: string) => Promise<CryptoKey | null>;
  /**
   * Test seam: override the SD-JWT presentation validation. Production use
   * relies on the real @askmi/oid4vp `validateSDJWTPresentation` path.
   */
  presentationValidator?: PresentationValidator;
}

/** The ADOPT-0 presentation validation seam (real path by default). */
export type PresentationValidator = (opts: {
  vpTokenString: string;
  presentationSubmission: unknown;
  request: {
    response_type: 'vp_token';
    client_id: string;
    redirect_uri: string;
    nonce: string;
    presentation_definition: { id: string; input_descriptors: [] };
    response_mode: 'direct_post';
    state?: string;
  };
  issuerPublicKey: CryptoKey;
  checkRevocation: boolean;
  checkTrust: boolean;
}) => Promise<{ ok: boolean; disclosedClaims?: Record<string, unknown>; errors: string[] }>;

/** Core interface (transport-neutral; no Express types). */
export interface AskMIConnect {
  createSession(input: CreateSessionInput): Promise<CreateSessionResult>;
  markWalletOpened(sessionId: string): Promise<WalletOpenedResult>;
  completeSession(input: CompleteSessionInput): Promise<CompleteSessionResult>;
  getSession(sessionId: string): Promise<GetSessionResult>;
  /** Persist terminal failure after an unexpected transport/core exception; never overwrite terminal state. */
  failSession(sessionId: string): Promise<CompleteSessionResult>;
}

export interface CreateSessionInput {
  policyId: AskMIConnectPolicyId;
  returnUrl?: string;
}

export type CreateSessionResult =
  | { ok: true; session: AskMIConnectSession; handoff: AskMIHandoff }
  | { ok: false; code: 'UNKNOWN_POLICY' };

export interface WalletOpenedResult {
  ok: boolean;
  code?: 'UNKNOWN_SESSION' | 'SESSION_TERMINAL' | 'SESSION_EXPIRED';
}

export interface CompleteSessionInput {
  sessionId: string;
  /** Raw wallet presentation body (ADOPT-0 /oid4vp-present payload shape). */
  body: PresentationRequestBody;
}

export interface PresentationRequestBody {
  vp_token?: unknown;
  presentation_submission?: unknown;
  state?: unknown;
  [key: string]: unknown;
}

export type CompleteSessionResult =
  | { ok: true; session: AskMIConnectSession }
  | { ok: false; code: AskMIConnectErrorCode; message: string };

export type GetSessionResult =
  | { ok: true; session: AskMIConnectSession }
  | { ok: false; code: 'UNKNOWN_SESSION' };
