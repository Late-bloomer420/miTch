import type { AuthorizationRequest } from '@askmi/oid4vp';
import { ASKMI_DEMO } from '@askmi/shared-types';

export function parseConnectHandoff(search: string) {
  const params = new URLSearchParams(search);
  const requestUri = params.get('request_uri');
  if (!requestUri) return null;
  const sessionId = params.get('state');
  const expectedNonce = params.get('nonce');
  if (!sessionId || !expectedNonce) throw new Error('Incomplete Connect handoff');
  const uri = new URL(requestUri);
  if (
    !['http:', 'https:'].includes(uri.protocol) ||
    uri.username ||
    uri.password ||
    uri.search ||
    uri.hash ||
    uri.pathname !== `/askmi/connect/sessions/${encodeURIComponent(sessionId)}/request`
  ) {
    throw new Error('Invalid Connect request endpoint');
  }
  return {
    scenario: 'liquor-store',
    endpoint: uri.origin,
    verifier: ASKMI_DEMO.verifierDid,
    sessionId,
    requestUri,
    expectedNonce,
  };
}

export async function loadConnectRequest(
  input: { requestUri: string; expectedNonce: string; sessionId: string; endpoint: string },
  fetcher: typeof fetch = fetch
): Promise<AuthorizationRequest> {
  const response = await fetcher(input.requestUri, { redirect: 'error', cache: 'no-store' });
  if (!response.ok) throw new Error('Connect request is unavailable or terminal');
  const { authRequest: auth } = (await response.json()) as { authRequest: AuthorizationRequest };
  const expectedEndpoint = `${input.endpoint}/askmi/connect/sessions/${encodeURIComponent(input.sessionId)}/presentation`;
  if (
    !auth ||
    auth.state !== input.sessionId ||
    auth.nonce !== input.expectedNonce ||
    auth.redirect_uri !== expectedEndpoint ||
    typeof auth.client_id !== 'string' ||
    !auth.client_id ||
    auth.response_type !== 'vp_token' ||
    auth.response_mode !== 'direct_post'
  ) {
    throw new Error('Connect request does not match this handoff');
  }
  return auth;
}

export function presentationAccepted(
  responseOk: boolean,
  body: { ok?: boolean; status?: string; result?: { eligible?: boolean } }
): boolean {
  if (!responseOk) return false;
  if (body.status !== undefined) return body.status === 'verified' && body.result?.eligible === true;
  return body.ok === true;
}
