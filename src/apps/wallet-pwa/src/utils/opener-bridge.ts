/**
 * Popup bridge intake (G-120, #239).
 *
 * A page that opens the wallet in a popup may hand it an OID4VP request with
 * postMessage. Any window can post to the wallet, so a message counts only when
 * it comes from the window that opened the wallet and that window is at an
 * origin the deployment listed in VITE_WALLET_OPENER_ORIGINS. With nothing
 * listed, the bridge is off.
 *
 * This establishes who sent the message. It does not authenticate the verifier
 * named inside it; that is tracked in #183.
 */

export interface OpenerRequest {
  scenario: string;
  endpoint: string;
  verifier: string;
  sessionId: string;
}

const REQUEST_TYPES = new Set(['ASKMI_OID4VP_REQUEST', 'MITCH_OID4VP_REQUEST']);

/** Parses a comma-separated list into http(s) origins; unusable entries are dropped. */
export function parseOpenerOrigins(raw: string | undefined): string[] {
  const origins: string[] = [];
  for (const entry of (raw ?? '').split(',')) {
    try {
      const url = new URL(entry.trim());
      if (url.protocol === 'https:' || url.protocol === 'http:') origins.push(url.origin);
    } catch {
      // Not a URL: ignore the entry.
    }
  }
  return origins;
}

/** The request carried by a message, or null unless the opener sent it from an allowed origin. */
export function readOpenerRequest(
  event: { origin: string; source: unknown; data: unknown },
  opener: unknown,
  allowedOrigins: readonly string[]
): OpenerRequest | null {
  if (!opener || event.source !== opener) return null;
  if (!allowedOrigins.includes(event.origin)) return null;
  const data = event.data as Record<string, unknown> | null;
  if (typeof data !== 'object' || data === null || !REQUEST_TYPES.has(data.type as string)) {
    return null;
  }
  const { scenario, endpoint, verifier, sessionId } = data;
  const fields = [scenario, endpoint, verifier, sessionId];
  if (!fields.every((field) => typeof field === 'string' && field !== '')) return null;
  return { scenario, endpoint, verifier, sessionId } as OpenerRequest;
}
