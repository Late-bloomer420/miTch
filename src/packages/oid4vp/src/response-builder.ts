/**
 * OID4VP Response Builder — Wallet constructs the authorization response
 */

import type {
    AuthorizationRequest,
    AuthorizationResponse,
    PresentationSubmission,
    ValidationResult,
} from './types';
import { buildVPToken } from './vp-token';

// ─── Consent Decision ─────────────────────────────────────────────

export type ConsentDecision =
    | { granted: true; selectedCredentials: string[] }
    | { granted: false; reason: string };

// ─── Response Builder ─────────────────────────────────────────────

export interface BuildResponseOptions {
    request: AuthorizationRequest;
    holder: string;
    consent: ConsentDecision;
}

/**
 * Build an OID4VP Authorization Response from a user consent decision.
 * Returns error if consent was denied.
 */
export function buildAuthorizationResponse(
    opts: BuildResponseOptions
): ValidationResult<AuthorizationResponse> {
    const { request, holder, consent } = opts;

    if (!consent.granted) {
        return {
            ok: false,
            error: `User denied: ${consent.reason}`,
            code: 'USER_DENIED',
        };
    }

    if (consent.selectedCredentials.length === 0) {
        return {
            ok: false,
            error: 'No credentials selected',
            code: 'NO_CREDENTIALS',
        };
    }

    const vpToken = buildVPToken({
        holder,
        credentials: consent.selectedCredentials,
        definition: request.presentation_definition,
        format: 'sd-jwt',
    });

    const token = typeof vpToken.vp_token === 'string'
        ? vpToken.vp_token
        : (vpToken.vp_token as string[])[0];

    return {
        ok: true,
        value: {
            vp_token: token,
            presentation_submission: vpToken.presentation_submission,
            state: request.state,
        },
    };
}

/**
 * Encode an authorization response for direct_post submission.
 * Returns URL-encoded form body.
 */
export function encodeDirectPost(response: AuthorizationResponse): string {
    const params = new URLSearchParams();

    const token = typeof response.vp_token === 'string'
        ? response.vp_token
        : JSON.stringify(response.vp_token);

    params.set('vp_token', token);
    params.set('presentation_submission', JSON.stringify(response.presentation_submission));

    if (response.state) {
        params.set('state', response.state);
    }

    return params.toString();
}

/**
 * Decode a direct_post form body back into an authorization response.
 */
export function decodeDirectPost(body: string): ValidationResult<AuthorizationResponse> {
    const params = new URLSearchParams(body);

    const vpToken = params.get('vp_token');
    const submissionStr = params.get('presentation_submission');

    if (!vpToken) {
        return { ok: false, error: 'Missing vp_token', code: 'MISSING_VP_TOKEN' };
    }

    if (!submissionStr) {
        return { ok: false, error: 'Missing presentation_submission', code: 'MISSING_SUBMISSION' };
    }

    let submission: PresentationSubmission;
    try {
        submission = JSON.parse(submissionStr);
    } catch {
        return { ok: false, error: 'Invalid presentation_submission JSON', code: 'INVALID_SUBMISSION' };
    }

    return {
        ok: true,
        value: {
            vp_token: vpToken,
            presentation_submission: submission,
            state: params.get('state') ?? undefined,
        },
    };
}
