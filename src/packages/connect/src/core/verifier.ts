/**
 * ADOPT-1.2 framework-agnostic Connect core.
 *
 * Wraps the existing ADOPT-0 verifier path (`@askmi/oid4vp`
 * `validateSDJWTPresentation` + trust-gated issuer key resolution) behind the
 * ADOPT-1.1 session contract. Transport-neutral: this module imports no
 * Express types. Fail-closed: any ambiguity maps to a stable error code and
 * a `failed` terminal session, never to `verified`.
 */

import { newCorrelationId } from '@askmi/shared-types';

import { validateSDJWTPresentation } from '@askmi/oid4vp';

import { buildAskMIHandoff } from '../browser/handoff';

import { evaluatePolicyResult, lookupPolicy, provenanceFor, sanitizeCreateInput } from './policies';
import { InMemoryAskMIConnectSessionStore } from './session-store';
import type {
  AskMIConnect,
  AskMIConnectConfig,
  AskMIConnectErrorCode,
  AskMIConnectSession,
  CompleteSessionInput,
  CompleteSessionResult,
  CreateSessionInput,
  CreateSessionResult,
  GetSessionResult,
  PresentationRequestBody,
  PresentationValidator,
  WalletOpenedResult,
} from './types';

const DEFAULT_SESSION_TTL_MS = 5 * 60 * 1000;
const SESSION_ID_PREFIX = 'askmi_sess_';

/** Terminal statuses: no transition out (ADOPT-1.1 state machine). */
function isTerminal(session: AskMIConnectSession): boolean {
  return (
    session.status === 'verified' || session.status === 'failed' || session.status === 'expired'
  );
}

function randomNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function newSessionId(): string {
  return SESSION_ID_PREFIX + globalThis.crypto.randomUUID();
}

/**
 * Linear trailing-slash trim. Deliberately regex-free: CodeQL flags
 * `/\/+$/` as a polynomial regex on uncontrolled data.
 */
function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
  return value.slice(0, end);
}

function presentationEndpoint(audienceBaseUrl: string, sessionId: string): string {
  const base = trimTrailingSlashes(audienceBaseUrl);
  return `${base}/askmi/connect/sessions/${encodeURIComponent(sessionId)}/presentation`;
}

/** Extract the `iss` of an SD-JWT VP token without verifying it (trust-gated afterwards). */
function extractIss(vpTokenString: string): string {
  try {
    const issuerJwt = vpTokenString.split('~')[0];
    const payloadSegment = issuerJwt.split('.')[1] ?? '';
    const normalized = payloadSegment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
    const json = atob(padded);
    const parsed = JSON.parse(json) as { iss?: unknown };
    return typeof parsed.iss === 'string' ? parsed.iss : '';
  } catch {
    return '';
  }
}

/**
 * The legacy simulated `/wallet-present` route is driven by `scenarioId`
 * (self-contained scenario claims, ephemeral issuer keys). A body carrying
 * that marker can never satisfy the Connect flow.
 */
function looksLikeSimulatedRoute(body: PresentationRequestBody): boolean {
  return (
    ('scenarioId' in body && typeof body.scenarioId === 'string') ||
    ('scenario' in body && typeof body.scenario === 'string')
  );
}

/**
 * Map raw validator error strings onto the stable ADOPT-1.1 error codes. The
 * underlying ADOPT-0 API returns message strings, not codes; this mapping is
 * the single place where raw text is converted, and it fails closed
 * (unknown text -> SIGNATURE_INVALID, never a success path).
 */
function mapValidationError(errors: readonly string[]): {
  code: AskMIConnectErrorCode;
  message: string;
} {
  const first = errors[0] ?? 'presentation validation failed';
  const text = errors.join(' | ');
  if (/nonce/i.test(text)) {
    return { code: 'WRONG_NONCE', message: 'Presentation nonce does not match this session.' };
  }
  if (/aud(ience)?/i.test(text)) {
    return {
      code: 'WRONG_AUDIENCE',
      message: 'Presentation was not issued for this verifier session.',
    };
  }
  if (/cnf|key binding|holder/i.test(text)) {
    return { code: 'SIGNATURE_INVALID', message: 'Holder binding verification failed.' };
  }
  if (/trust|issuer/i.test(text)) {
    return { code: 'UNTRUSTED_ISSUER', message: 'Issuer is not trusted or cannot be resolved.' };
  }
  if (/revok|status/i.test(text)) {
    return {
      code: 'POLICY_DENIED',
      message: 'Credential is revoked or its status denies the request.',
    };
  }
  if (/signature|verify|expired|expiry|tamper/i.test(text)) {
    return { code: 'SIGNATURE_INVALID', message: 'Cryptographic verification failed.' };
  }
  return { code: 'SIGNATURE_INVALID', message: first };
}

export function createAskMIConnect(config: AskMIConnectConfig): AskMIConnect {
  const ttlMs = config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const store = config.store ?? new InMemoryAskMIConnectSessionStore();
  const resolveIssuerKey: (iss: string) => Promise<CryptoKey | null> =
    config.issuerKeyResolver ?? (async () => null);
  const validate: PresentationValidator =
    config.presentationValidator ??
    (async (opts) =>
      validateSDJWTPresentation({
        vpTokenString: opts.vpTokenString,
        presentationSubmission: opts.presentationSubmission as never,
        request: opts.request,
        issuerPublicKey: opts.issuerPublicKey,
        checkRevocation: opts.checkRevocation,
        checkTrust: opts.checkTrust,
      }));

  async function getLiveSession(
    sessionId: string
  ): Promise<
    | { ok: false; code: 'UNKNOWN_SESSION' }
    | { ok: false; code: 'SESSION_TERMINAL' }
    | { ok: false; code: 'SESSION_EXPIRED' }
    | { ok: true; session: AskMIConnectSession }
  > {
    const session = await store.get(sessionId);
    if (!session) return { ok: false, code: 'UNKNOWN_SESSION' };
    if (isTerminal(session)) return { ok: false, code: 'SESSION_TERMINAL' };
    if (Date.parse(session.expiresAt) <= Date.now()) {
      await store.update({ ...session, status: 'expired' });
      return { ok: false, code: 'SESSION_EXPIRED' };
    }
    return { ok: true, session };
  }

  return {
    async createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
      const clean = sanitizeCreateInput(input);
      const policy = lookupPolicy(clean.policyId);
      if (!policy) return { ok: false, code: 'UNKNOWN_POLICY' };
      const sessionId = newSessionId();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + ttlMs);
      const session: AskMIConnectSession = {
        sessionId,
        status: 'pending',
        createdAt: createdAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        nonce: randomNonce(),
        audience: presentationEndpoint(config.audienceBaseUrl, sessionId),
        verifierDid: config.verifierDid,
        policyId: policy.id,
        policyVersion: policy.version,
        correlationId: newCorrelationId(),
        ...(clean.returnUrl !== undefined ? { returnUrl: clean.returnUrl } : {}),
      };
      await store.create(session);
      return {
        ok: true,
        session,
        handoff: buildAskMIHandoff({
          walletBaseUrl: config.walletBaseUrl,
          sessionId,
          nonce: session.nonce,
          presentationEndpoint: session.audience,
          ...(clean.returnUrl !== undefined ? { returnUrl: clean.returnUrl } : {}),
        }),
      };
    },

    async markWalletOpened(sessionId: string): Promise<WalletOpenedResult> {
      const live = await getLiveSession(sessionId);
      if (!live.ok) return { ok: false, code: live.code };
      if (live.session.status === 'wallet_opened') return { ok: true };
      await store.update({ ...live.session, status: 'wallet_opened' });
      return { ok: true };
    },

    async completeSession(input: CompleteSessionInput): Promise<CompleteSessionResult> {
      const fail = async (
        session: AskMIConnectSession,
        code: AskMIConnectErrorCode,
        message: string
      ): Promise<CompleteSessionResult> => {
        await store.update({ ...session, status: 'failed', errorCode: code });
        return { ok: false, code, message };
      };

      // One-shot consume: a second completion attempt for the same session
      // cannot race the first into a second `verified`.
      const claimed = await store.consume(input.sessionId);
      if (!claimed) {
        const existing = await store.get(input.sessionId);
        if (!existing) return { ok: false, code: 'UNKNOWN_SESSION', message: 'Session not found.' };
        if (isTerminal(existing)) {
          return {
            ok: false,
            code: existing.status === 'verified' ? 'REPLAY_DETECTED' : 'SESSION_TERMINAL',
            message:
              existing.status === 'verified'
                ? 'Session already verified; presentations are one-shot.'
                : 'Session is already in a terminal state.',
          };
        }
        return { ok: false, code: 'REPLAY_DETECTED', message: 'Session attempt already consumed.' };
      }
      const session = claimed;

      const live = await getLiveSession(input.sessionId);
      if (!live.ok) {
        if (live.code === 'SESSION_EXPIRED') {
          await store.update({ ...session, status: 'expired' });
          return { ok: false, code: 'SESSION_EXPIRED', message: 'Session expired.' };
        }
        return { ok: false, code: 'UNKNOWN_SESSION', message: 'Session not found.' };
      }

      const body = input.body;
      if (looksLikeSimulatedRoute(body)) {
        return fail(
          session,
          'SIMULATED_ROUTE_REJECTED',
          'Legacy simulated wallet-present payloads cannot satisfy the Connect flow.'
        );
      }
      if (typeof body.vp_token !== 'string' || body.vp_token.length === 0) {
        return fail(session, 'MALFORMED_PRESENTATION', 'Missing vp_token.');
      }
      if (
        typeof body.presentation_submission !== 'object' ||
        body.presentation_submission === null
      ) {
        return fail(session, 'MALFORMED_PRESENTATION', 'Missing presentation_submission.');
      }
      if (body.state !== undefined && body.state !== session.sessionId) {
        return fail(session, 'WRONG_NONCE', 'Presentation state does not match this session.');
      }

      const iss = extractIss(body.vp_token);
      if (!iss) {
        return fail(session, 'UNTRUSTED_ISSUER', 'Credential issuer cannot be determined.');
      }
      const issuerPublicKey = await resolveIssuerKey(iss);
      if (!issuerPublicKey) {
        return fail(session, 'UNTRUSTED_ISSUER', 'Issuer is not trusted or cannot be resolved.');
      }

      const request = {
        response_type: 'vp_token' as const,
        client_id: session.verifierDid,
        redirect_uri: presentationEndpoint(config.audienceBaseUrl, session.sessionId),
        nonce: session.nonce,
        presentation_definition: { id: 'askmi-connect', input_descriptors: [] as [] },
        response_mode: 'direct_post' as const,
        state: session.sessionId,
      };

      let validation;
      try {
        validation = await validate({
          vpTokenString: body.vp_token,
          presentationSubmission: body.presentation_submission,
          request,
          issuerPublicKey,
          checkRevocation: true,
          checkTrust: false,
        });
      } catch (e) {
        return fail(session, 'SIGNATURE_INVALID', 'Cryptographic verification failed.');
      }
      if (!validation.ok) {
        const mapped = mapValidationError(validation.errors);
        return fail(session, mapped.code, mapped.message);
      }

      const disclosedClaims = validation.disclosedClaims ?? {};
      const policy = lookupPolicy(session.policyId);
      if (!policy) {
        return fail(session, 'INTERNAL_ERROR', 'Registered policy disappeared.');
      }
      const missing = policy.requiredClaims.filter((claim) => !(claim in disclosedClaims));
      if (missing.length > 0) {
        return fail(
          session,
          'INSUFFICIENT_CLAIMS',
          'Required claims are missing after valid verification.'
        );
      }

      const result = evaluatePolicyResult(policy, disclosedClaims);
      if (!result.eligible) {
        return fail(
          session,
          'POLICY_DENIED',
          'Policy evaluated the presented claims as not eligible.'
        );
      }

      const verified: AskMIConnectSession = {
        ...session,
        status: 'verified',
        result,
        verification: {
          cryptographic: 'passed',
          issuerTrust: 'passed',
          policy: 'allowed',
          userApproval: 'presentation_received',
        },
        provenance: provenanceFor(policy, disclosedClaims, session.correlationId),
      };
      await store.update(verified);
      return { ok: true, session: verified };
    },

    async getSession(sessionId: string): Promise<GetSessionResult> {
      const session = await store.get(sessionId);
      if (!session) return { ok: false, code: 'UNKNOWN_SESSION' };
      if (!isTerminal(session) && Date.parse(session.expiresAt) <= Date.now()) {
        await store.update({ ...session, status: 'expired' });
        return { ok: true, session: { ...session, status: 'expired' } };
      }
      return { ok: true, session };
    },
  };
}
