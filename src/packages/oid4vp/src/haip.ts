/**
 * OpenID4VC High Assurance Interoperability Profile (HAIP)
 * https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 *
 * Implements:
 * - HAIP-compliant Presentation Definition builder (limit_disclosure=required)
 * - Response Mode: direct_post.jwt (encrypted + signed JWE/JWT response)
 * - Client ID Scheme: verifier_attestation
 * - Verifier Attestation JWT validation
 * - HAIP format constraint enforcement (sd-jwt vc preferred, mdoc stub)
 */

import { SignJWT, jwtVerify, exportJWK, importJWK, CompactEncrypt, compactDecrypt } from 'jose';
import type { JWK } from 'jose';
import type {
    PresentationDefinition,
    InputDescriptor,
    DescriptorConstraints,
    AuthorizationRequest,
} from './types';

// ─── Types ────────────────────────────────────────────────────────────────────

export type HAIPFormat = 'vc+sd-jwt' | 'mso_mdoc';

export interface HAIPPresentationConstraints {
    /** Credential format required */
    format: HAIPFormat;
    /** Claim paths to request (JSONPath for sd-jwt, CBOR paths for mdoc) */
    claimPaths: string[];
    /** Claim name for human-readable purpose */
    purpose?: string;
}

export interface HAIPAuthorizationRequest extends AuthorizationRequest {
    /** HAIP requires client_id_scheme = verifier_attestation */
    client_id_scheme: 'verifier_attestation';
    /** Verifier Attestation JWT */
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation';
    client_assertion: string;
    /** HAIP requires direct_post.jwt */
    response_mode: 'direct_post.jwt';
}

export interface VerifierAttestationPayload {
    /** Issuer = trust anchor */
    iss: string;
    /** Subject = verifier's client_id */
    sub: string;
    /** Issued at */
    iat: number;
    /** Expiry */
    exp: number;
    /** Confirmation: verifier's public key */
    cnf: { jwk: JWK };
    /** Verifier's redirect_uris whitelist */
    redirect_uris?: string[];
}

export interface HAIPRequestValidationResult {
    ok: boolean;
    request?: HAIPAuthorizationRequest;
    verifierPayload?: VerifierAttestationPayload;
    errors: string[];
}

export interface DirectPostJWTResponse {
    /** Encrypted + signed response (JWE wrapping signed JWT) */
    response: string;
}

// ─── HAIP Presentation Definition Builder ────────────────────────────────────

/**
 * Build a HAIP-compliant Presentation Definition.
 * Enforces: limit_disclosure=required, format constraints.
 */
export function buildHAIPPresentationDefinition(
    id: string,
    descriptors: HAIPPresentationConstraints[]
): PresentationDefinition {
    const inputDescriptors: InputDescriptor[] = descriptors.map((desc, idx) => {
        const constraints: DescriptorConstraints = {
            limit_disclosure: 'required', // HAIP MUST
            fields: desc.claimPaths.map(path => ({
                path: [path],
                filter: undefined,
                optional: false,
            })),
        };

        return {
            id: `descriptor-${idx}`,
            name: desc.purpose ?? `Credential ${idx + 1}`,
            purpose: desc.purpose,
            constraints,
            // HAIP format annotation (stored in format field per DIF PE spec)
            ...(desc.format === 'vc+sd-jwt'
                ? { format: { 'vc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } } }
                : { format: { mso_mdoc: { alg: ['ES256'] } } }),
        };
    });

    return {
        id,
        input_descriptors: inputDescriptors,
    };
}

// ─── Verifier Attestation JWT ─────────────────────────────────────────────────

/**
 * Issue a Verifier Attestation JWT (for HAIP client_id_scheme=verifier_attestation).
 * Called by a trust anchor.
 */
export async function issueVerifierAttestation(
    opts: {
        iss: string;
        verifierClientId: string;
        verifierPublicKey: CryptoKey;
        redirectUris?: string[];
        validitySeconds?: number;
    },
    trustAnchorPrivateKey: CryptoKey
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const verifierJWK = await exportJWK(opts.verifierPublicKey);
    delete verifierJWK.d;

    const payload: VerifierAttestationPayload = {
        iss: opts.iss,
        sub: opts.verifierClientId,
        iat: now,
        exp: now + (opts.validitySeconds ?? 86400),
        cnf: { jwk: verifierJWK },
    };
    if (opts.redirectUris) payload.redirect_uris = opts.redirectUris;

    return new SignJWT(payload as unknown as Record<string, unknown>)
        .setProtectedHeader({ alg: 'ES256', typ: 'verifier-attestation+jwt' })
        .sign(trustAnchorPrivateKey);
}

/**
 * Validate a Verifier Attestation JWT (wallet-side).
 * Wallet MUST verify this before sending a presentation.
 */
export async function validateVerifierAttestation(
    attestationJwt: string,
    trustAnchorPublicKey: CryptoKey | JWK,
    opts?: { expectedClientId?: string; expectedRedirectUri?: string }
): Promise<{ ok: boolean; payload?: VerifierAttestationPayload; errors: string[] }> {
    const errors: string[] = [];

    let payload: VerifierAttestationPayload;
    try {
        const key = trustAnchorPublicKey instanceof CryptoKey
            ? trustAnchorPublicKey
            : await importJWK(trustAnchorPublicKey) as CryptoKey;
        const result = await jwtVerify(attestationJwt, key, {
            typ: 'verifier-attestation+jwt',
            clockTolerance: 30,
        });
        payload = result.payload as unknown as VerifierAttestationPayload;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`Verifier Attestation verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
        errors.push('Verifier Attestation expired');
    }

    if (opts?.expectedClientId && payload.sub !== opts.expectedClientId) {
        errors.push(`Verifier client_id mismatch: expected ${opts.expectedClientId}, got ${payload.sub}`);
    }

    if (opts?.expectedRedirectUri && payload.redirect_uris) {
        if (!payload.redirect_uris.includes(opts.expectedRedirectUri)) {
            errors.push(`redirect_uri ${opts.expectedRedirectUri} not in verifier's allowed list`);
        }
    }

    return {
        ok: errors.length === 0,
        payload: errors.length === 0 ? payload : undefined,
        errors,
    };
}

// ─── HAIP Authorization Request Validation ────────────────────────────────────

/**
 * Validate a HAIP Authorization Request (wallet-side).
 * Enforces HAIP-specific constraints on top of base OID4VP.
 */
export async function validateHAIPRequest(
    raw: unknown,
    trustAnchorPublicKey: CryptoKey | JWK
): Promise<HAIPRequestValidationResult> {
    if (!raw || typeof raw !== 'object') {
        return { ok: false, errors: ['Request must be an object'] };
    }
    const r = raw as Record<string, unknown>;
    const errors: string[] = [];

    // HAIP: client_id_scheme must be verifier_attestation
    if (r['client_id_scheme'] !== 'verifier_attestation') {
        errors.push(`HAIP requires client_id_scheme=verifier_attestation, got: ${r['client_id_scheme']}`);
    }

    // HAIP: response_mode must be direct_post.jwt
    if (r['response_mode'] !== 'direct_post.jwt') {
        errors.push(`HAIP requires response_mode=direct_post.jwt, got: ${r['response_mode']}`);
    }

    // HAIP: client_assertion_type check
    if (r['client_assertion_type'] !== 'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation') {
        errors.push('HAIP requires client_assertion_type=jwt-client-attestation');
    }

    // Required base fields
    if (typeof r['client_id'] !== 'string' || !r['client_id']) {
        errors.push('Missing client_id');
    }
    if (typeof r['nonce'] !== 'string' || !r['nonce']) {
        errors.push('Missing nonce');
    }

    if (errors.length > 0) {
        return { ok: false, errors };
    }

    // Validate the Verifier Attestation JWT
    if (typeof r['client_assertion'] !== 'string') {
        return { ok: false, errors: ['Missing client_assertion (Verifier Attestation JWT)'] };
    }

    const attResult = await validateVerifierAttestation(
        r['client_assertion'] as string,
        trustAnchorPublicKey,
        { expectedClientId: r['client_id'] as string }
    );

    if (!attResult.ok) {
        return { ok: false, errors: attResult.errors };
    }

    // Validate limit_disclosure=required on all descriptors
    const pd = r['presentation_definition'] as Record<string, unknown> | undefined;
    if (pd?.input_descriptors && Array.isArray(pd.input_descriptors)) {
        for (const desc of pd.input_descriptors) {
            const d = desc as Record<string, unknown>;
            const constraints = d['constraints'] as Record<string, unknown> | undefined;
            if (constraints?.limit_disclosure !== 'required') {
                errors.push(`HAIP: input_descriptor ${d['id']} must have limit_disclosure=required`);
            }
        }
    }

    if (errors.length > 0) {
        return { ok: false, errors };
    }

    return {
        ok: true,
        request: r as unknown as HAIPAuthorizationRequest,
        verifierPayload: attResult.payload,
        errors: [],
    };
}

// ─── direct_post.jwt Response Mode ───────────────────────────────────────────

/**
 * Encrypt a VP response for direct_post.jwt mode.
 * Response is a JWE wrapping the signed VP token JWT.
 */
export async function encryptDirectPostResponse(
    vpToken: string,
    verifierPublicKey: CryptoKey | JWK
): Promise<DirectPostJWTResponse> {
    const recipientKey = verifierPublicKey instanceof CryptoKey
        ? verifierPublicKey
        : await importJWK(verifierPublicKey) as CryptoKey;

    // Wrap the VP token in a JWE using ECDH-ES+A256KW
    const encoder = new TextEncoder();
    const jwePayload = JSON.stringify({ vp_token: vpToken });

    // For ECDH-based encryption we need an EC public key
    // Build a compact JWE: ECDH-ES + A256GCM
    const encrypted = await new CompactEncrypt(encoder.encode(jwePayload))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(recipientKey);

    return { response: encrypted };
}

/**
 * Decrypt a direct_post.jwt response (verifier-side).
 */
export async function decryptDirectPostResponse(
    encryptedResponse: string,
    verifierPrivateKey: CryptoKey
): Promise<{ vp_token: string }> {
    const { plaintext } = await compactDecrypt(encryptedResponse, verifierPrivateKey);
    const decoded = new TextDecoder().decode(plaintext);
    return JSON.parse(decoded) as { vp_token: string };
}
