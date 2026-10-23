/**
 * ADOPT-1.2 thin Express adapter over the ADOPT-1.1 session contract.
 *
 * Rules (ADOPT-1.2):
 * - no session state in module globals (all state lives in the configured store);
 * - no raw exception text in HTTP responses (stable codes only);
 * - no raw credential payloads or disclosed values in status responses.
 *
 * This is a subpath export (`@askmi/connect/express`) — the core itself
 * imports no Express types.
 */

import { Router } from 'express';

import type { AskMIConnect, AskMIConnectErrorCode, AskMIConnectSession } from '../core/types';

/** HTTP status for each stable Connect error code (ADOPT-1.1 failure table). */
function httpStatusFor(code: AskMIConnectErrorCode): number {
  switch (code) {
    case 'UNKNOWN_POLICY':
    case 'MALFORMED_PRESENTATION':
    case 'SIMULATED_ROUTE_REJECTED':
      return 400;
    case 'WRONG_AUDIENCE':
    case 'WRONG_NONCE':
    case 'UNTRUSTED_ISSUER':
    case 'SIGNATURE_INVALID':
    case 'INSUFFICIENT_CLAIMS':
    case 'POLICY_DENIED':
      return 403;
    case 'UNKNOWN_SESSION':
      return 404;
    case 'SESSION_TERMINAL':
    case 'REPLAY_DETECTED':
      return 409;
    case 'SESSION_EXPIRED':
      return 410;
    case 'INTERNAL_ERROR':
      return 500;
  }
}

/** PII-minimal session projection for HTTP responses (ADOPT-1.1 route bodies). */
function sessionResponseBody(session: AskMIConnectSession): Record<string, unknown> {
  const base: Record<string, unknown> = {
    sessionId: session.sessionId,
    status: session.status,
    expiresAt: session.expiresAt,
    policy: { id: session.policyId, version: session.policyVersion },
  };
  if (session.status === 'verified') {
    base.result = session.result;
    base.verification = session.verification;
    base.provenance = session.provenance;
  }
  return base;
}

/**
 * Build the Connect routes:
 * - POST   /askmi/connect/sessions
 * - POST   /askmi/connect/sessions/:sessionId/opened
 * - POST   /askmi/connect/sessions/:sessionId/presentation
 * - GET    /askmi/connect/sessions/:sessionId
 */
export function askmiConnectExpressRouter(connect: AskMIConnect): Router {
  const router = Router();

  router.post('/askmi/connect/sessions', async (req, res) => {
    const body = (req.body ?? {}) as { policyId?: unknown; returnUrl?: unknown };
    const result = await connect.createSession({
      policyId: body.policyId as never,
      ...(typeof body.returnUrl === 'string' ? { returnUrl: body.returnUrl } : {}),
    });
    if (!result.ok) {
      res
        .status(400)
        .json({ error: { code: 'UNKNOWN_POLICY', message: 'policyId is not registered.' } });
      return;
    }
    res.status(201).json({ ...sessionResponseBody(result.session), handoff: result.handoff });
  });

  router.post('/askmi/connect/sessions/:sessionId/opened', async (req, res) => {
    const result = await connect.markWalletOpened(req.params.sessionId);
    if (result.ok) {
      res.status(204).send();
      return;
    }
    res.status(httpStatusFor(result.code!)).json({
      sessionId: req.params.sessionId,
      status: 'failed',
      error: { code: result.code, message: 'Session cannot transition to wallet_opened.' },
    });
  });

  router.post('/askmi/connect/sessions/:sessionId/presentation', async (req, res) => {
    const result = await connect.completeSession({
      sessionId: req.params.sessionId,
      body: (req.body ?? {}) as Record<string, unknown>,
    });
    if (result.ok) {
      res.status(200).json(sessionResponseBody(result.session));
      return;
    }
    res.status(httpStatusFor(result.code)).json({
      sessionId: req.params.sessionId,
      status: 'failed',
      error: { code: result.code, message: result.message },
    });
  });

  router.get('/askmi/connect/sessions/:sessionId', async (req, res) => {
    const result = await connect.getSession(req.params.sessionId);
    if (!result.ok) {
      res.status(404).json({
        sessionId: req.params.sessionId,
        status: 'failed',
        error: { code: 'UNKNOWN_SESSION', message: 'Session not found.' },
      });
      return;
    }
    res.status(200).json(sessionResponseBody(result.session));
  });

  return router;
}
