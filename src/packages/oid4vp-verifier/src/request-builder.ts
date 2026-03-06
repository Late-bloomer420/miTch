/**
 * OID4VP Verifier — Authorization Request builder
 */

import { randomBytes } from 'crypto';
import type { AuthorizationRequest, PresentationDefinition } from '@mitch/oid4vp';

export interface RequestBuilderOptions {
    clientId: string;
    redirectUri: string;
    definition: PresentationDefinition;
    state?: string;
    responseMode?: AuthorizationRequest['response_mode'];
}

/**
 * Build an OID4VP Authorization Request (verifier side).
 * Generates a fresh nonce for each request.
 */
export function buildAuthorizationRequest(opts: RequestBuilderOptions): AuthorizationRequest {
    return {
        response_type: 'vp_token',
        client_id: opts.clientId,
        redirect_uri: opts.redirectUri,
        nonce: randomBytes(16).toString('hex'),
        presentation_definition: opts.definition,
        state: opts.state ?? randomBytes(8).toString('hex'),
        response_mode: opts.responseMode ?? 'direct_post',
    };
}

/**
 * Encode an authorization request as query parameters (for JAR / request_uri).
 */
export function encodeAuthorizationRequest(req: AuthorizationRequest): string {
    const params = new URLSearchParams({
        response_type: req.response_type,
        client_id: req.client_id,
        redirect_uri: req.redirect_uri,
        nonce: req.nonce,
        presentation_definition: JSON.stringify(req.presentation_definition),
    });
    if (req.state) params.set('state', req.state);
    if (req.response_mode) params.set('response_mode', req.response_mode);
    return params.toString();
}
