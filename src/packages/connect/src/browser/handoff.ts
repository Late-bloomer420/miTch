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
  /** Server-owned request endpoint for wallets supporting the Connect flow. */
  requestUri?: string;
}

export interface AskMIHandoff {
  url: string;
  method: 'browser-redirect-or-qr';
  presentationEndpoint: string;
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

export function buildAskMIHandoff(input: BuildAskMIHandoffInput): AskMIHandoff {
  const base = trimTrailingSlashes(input.walletBaseUrl);
  const params = new URLSearchParams({ state: input.sessionId, nonce: input.nonce });
  if (input.returnUrl !== undefined) params.set('returnUrl', input.returnUrl);
  if (input.requestUri !== undefined) params.set('request_uri', input.requestUri);
  return {
    url: `${base}?${params.toString()}`,
    method: 'browser-redirect-or-qr',
    presentationEndpoint: input.presentationEndpoint,
  };
}
