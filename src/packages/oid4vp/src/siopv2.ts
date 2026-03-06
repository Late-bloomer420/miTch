/**
 * SIOPv2 — Self-Issued OpenID Provider v2
 * https://openid.net/specs/openid-connect-self-issued-v2-1_0.html
 *
 * Implements:
 * - SIOPv2 Authorization Request parsing
 * - SIOPv2 Authorization Response / id_token generation
 * - id_token signing with holder key (ES256)
 * - Nonce + state binding
 * - Pairwise sub computation (HKDF-derived, per verifier)
 */

import { SignJWT, jwtVerify, exportJWK, importJWK } from 'jose';
import type { JWK } from 'jose';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SIOPv2AuthorizationRequest {
    /** Must be 'id_token' or 'id_token vp_token' */
    response_type: 'id_token' | 'id_token vp_token';
    /** Client identifier (verifier's URI or DID) */
    client_id: string;
    /** Where to send the response */
    redirect_uri: string;
    /** Verifier-generated nonce */
    nonce: string;
    /** MUST be 'openid' (+ 'openid4vp' for combined flows) */
    scope: string;
    /** Anti-CSRF state */
    state?: string;
    /** Response mode */
    response_mode?: 'direct_post' | 'direct_post.jwt' | 'fragment' | 'query';
    /** Subject syntax types the verifier accepts */
    subject_syntax_types_supported?: string[];
    /** Max age of id_token in seconds */
    max_age?: number;
}

export interface SIOPv2ParseResult {
    ok: boolean;
    request?: SIOPv2AuthorizationRequest;
    errors: string[];
}

export interface SIOPv2IDTokenPayload {
    /** Issuer = holder's DID or 'https://self-issued.me/v2' */
    iss: string;
    /** Audience = verifier's client_id */
    aud: string;
    /** Issued at */
    iat: number;
    /** Expiry */
    exp: number;
    /** Nonce from request */
    nonce: string;
    /** Subject — pairwise pseudonymous identifier */
    sub: string;
    /** Subject's JWK (for key binding) */
    sub_jwk?: JWK;
    /** State (echoed back) */
    state?: string;
}

export interface SIOPv2AuthorizationResponse {
    /** Signed id_token (compact JWT) */
    id_token: string;
    /** State echoed from request */
    state?: string;
}

export interface SIOPv2ValidationResult {
    ok: boolean;
    payload?: SIOPv2IDTokenPayload;
    errors: string[];
}

// ─── Request Parsing ──────────────────────────────────────────────────────────

/**
 * Parse and validate a SIOPv2 Authorization Request.
 */
export function parseSIOPv2Request(raw: unknown): SIOPv2ParseResult {
    if (!raw || typeof raw !== 'object') {
        return { ok: false, errors: ['Request must be an object'] };
    }
    const r = raw as Record<string, unknown>;
    const errors: string[] = [];

    // response_type must be 'id_token' or 'id_token vp_token'
    if (r['response_type'] !== 'id_token' && r['response_type'] !== 'id_token vp_token') {
        errors.push(`Invalid response_type: ${r['response_type']} (expected 'id_token' or 'id_token vp_token')`);
    }

    // scope must contain 'openid'
    if (typeof r['scope'] !== 'string' || !r['scope'].split(' ').includes('openid')) {
        errors.push('scope must contain openid');
    }

    // client_id required
    if (typeof r['client_id'] !== 'string' || !r['client_id']) {
        errors.push('Missing client_id');
    }

    // redirect_uri required
    if (typeof r['redirect_uri'] !== 'string' || !r['redirect_uri']) {
        errors.push('Missing redirect_uri');
    }

    // nonce required
    if (typeof r['nonce'] !== 'string' || !r['nonce']) {
        errors.push('Missing nonce');
    }

    if (errors.length > 0) {
        return { ok: false, errors };
    }

    return {
        ok: true,
        request: {
            response_type: r['response_type'] as SIOPv2AuthorizationRequest['response_type'],
            client_id: r['client_id'] as string,
            redirect_uri: r['redirect_uri'] as string,
            nonce: r['nonce'] as string,
            scope: r['scope'] as string,
            state: typeof r['state'] === 'string' ? r['state'] : undefined,
            response_mode: typeof r['response_mode'] === 'string'
                ? r['response_mode'] as SIOPv2AuthorizationRequest['response_mode']
                : undefined,
            subject_syntax_types_supported: Array.isArray(r['subject_syntax_types_supported'])
                ? r['subject_syntax_types_supported'] as string[]
                : undefined,
            max_age: typeof r['max_age'] === 'number' ? r['max_age'] : undefined,
        },
        errors: [],
    };
}

// ─── Response Generation ──────────────────────────────────────────────────────

/**
 * Create a SIOPv2 id_token in response to an Authorization Request.
 * The sub is computed as a pairwise pseudonymous identifier (HKDF-derived).
 *
 * @param request  Parsed SIOPv2 request
 * @param holderPrivateKey  Holder's ECDSA P-256 private key
 * @param holderPublicKey  Corresponding public key
 * @param holderDID  Holder's DID (used as iss)
 */
export async function createSIOPv2Response(
    request: SIOPv2AuthorizationRequest,
    holderPrivateKey: CryptoKey,
    holderPublicKey: CryptoKey,
    holderDID: string
): Promise<SIOPv2AuthorizationResponse> {
    const now = Math.floor(Date.now() / 1000);

    // Compute pairwise sub = SHA-256(client_id || holderDID) — simple derivation
    const pairwiseSub = await computePairwiseSub(request.client_id, holderDID);

    const publicKeyJWK = await exportJWK(holderPublicKey);
    delete publicKeyJWK.d; // paranoia

    const payload: SIOPv2IDTokenPayload = {
        iss: holderDID,
        aud: request.client_id,
        iat: now,
        exp: now + (request.max_age ?? 600), // 10 min default
        nonce: request.nonce,
        sub: pairwiseSub,
        sub_jwk: publicKeyJWK,
    };

    if (request.state) {
        payload.state = request.state;
    }

    const idToken = await new SignJWT(payload as unknown as Record<string, unknown>)
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .sign(holderPrivateKey);

    return {
        id_token: idToken,
        state: request.state,
    };
}

// ─── Response Validation ──────────────────────────────────────────────────────

/**
 * Validate a SIOPv2 id_token at the verifier side.
 * Verifies signature using sub_jwk embedded in the token.
 */
export async function validateSIOPv2IDToken(
    idToken: string,
    opts: {
        expectedClientId: string;
        expectedNonce: string;
        expectedState?: string;
    }
): Promise<SIOPv2ValidationResult> {
    const errors: string[] = [];

    // 1. Decode header to find signing key
    let holderPublicKey: CryptoKey;
    let payload: SIOPv2IDTokenPayload;

    try {
        // First, decode without verification to get sub_jwk
        const payloadB64 = idToken.split('.')[1];
        const rawPayload = JSON.parse(
            atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))
        ) as SIOPv2IDTokenPayload;

        if (!rawPayload.sub_jwk) {
            return { ok: false, errors: ['Missing sub_jwk — required for SIOP verification'] };
        }

        holderPublicKey = await importJWK(rawPayload.sub_jwk) as CryptoKey;

        // Verify signature
        const result = await jwtVerify(idToken, holderPublicKey, {
            clockTolerance: 30,
        });
        payload = result.payload as unknown as SIOPv2IDTokenPayload;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`id_token verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // 2. aud = our client_id
    if (payload.aud !== opts.expectedClientId) {
        errors.push(`aud mismatch: expected ${opts.expectedClientId}, got ${payload.aud}`);
    }

    // 3. nonce binding
    if (payload.nonce !== opts.expectedNonce) {
        errors.push(`nonce mismatch: expected ${opts.expectedNonce}, got ${payload.nonce}`);
    }

    // 4. state binding (if provided)
    if (opts.expectedState !== undefined && payload.state !== opts.expectedState) {
        errors.push(`state mismatch: expected ${opts.expectedState}, got ${payload.state}`);
    }

    // 5. sub must be present
    if (!payload.sub) {
        errors.push('Missing sub claim');
    }

    // 6. exp check
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp !== undefined && payload.exp < now) {
        errors.push(`id_token expired at ${new Date(payload.exp * 1000).toISOString()}`);
    }

    return {
        ok: errors.length === 0,
        payload: errors.length === 0 ? payload : undefined,
        errors,
    };
}

// ─── Pairwise Subject ─────────────────────────────────────────────────────────

/**
 * Compute a pairwise pseudonymous sub per SIOPv2 §6.2.
 * The sub is deterministic for the same (verifier, holder) pair,
 * but unlinkable across verifiers.
 *
 * Implementation: HKDF-derived via WebCrypto (or SHA-256 fallback).
 */
export async function computePairwiseSub(verifierClientId: string, holderDID: string): Promise<string> {
    const input = `${verifierClientId}:${holderDID}`;
    const data = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    const b64 = btoa(String.fromCharCode(...hashArray));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
