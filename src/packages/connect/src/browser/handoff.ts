/**
 * ADOPT-1.2 browser handoff helper — a link builder, not a branded auth
 * product. The optional button UI is deferred until the server session
 * contract is green (prevents UI polish from hiding protocol mistakes).
 *
 * Subpath export `@askmi/connect/browser` — no server dependencies.
 */

export interface BuildAskMIHandoffInput {
  /** Wallet base URL (from the Connect config). */
  walletBaseUrl: string;
  /** The verifier-side session id to bind the handoff to. */
  sessionId: string;
  /** The session nonce, minted server-side with cryptographic randomness. */
  nonce: string;
  /** Absolute presentation endpoint the wallet posts the VP to. */
  presentationEndpoint: string;
  /** Optional display/navigation target after completion (never a trust source). */
  returnUrl?: string;
}

export interface AskMIHandoff {
  url: string;
  method: 'browser-redirect-or-qr';
  presentationEndpoint: string;
}

export function buildAskMIHandoff(input: BuildAskMIHandoffInput): AskMIHandoff {
  const base = input.walletBaseUrl.replace(/\/+$/, '');
  const params = new URLSearchParams({ state: input.sessionId, nonce: input.nonce });
  if (input.returnUrl !== undefined) params.set('returnUrl', input.returnUrl);
  return {
    url: `${base}?${params.toString()}`,
    method: 'browser-redirect-or-qr',
    presentationEndpoint: input.presentationEndpoint,
  };
}
