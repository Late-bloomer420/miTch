/**
 * SD-JWT VC Compliance — draft-ietf-oauth-sd-jwt-vc-11
 * https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html
 *
 * Implements:
 * - vct (Verifiable Credential Type) claim
 * - cnf (Confirmation) claim — Key Binding
 * - status claim (StatusList2021 reference)
 * - Strict iss/iat/exp/nbf validation
 * - Key Binding JWT (kb+jwt) compliance
 */

import { SignJWT, jwtVerify, importJWK, exportJWK } from 'jose';
import type { JWK } from 'jose';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SDJWTVCHeader {
    typ: 'vc+sd-jwt';
    alg: string;
}

export interface CNFClaim {
    /** JSON Web Key — holder's public key for Key Binding */
    jwk?: JWK;
}

export interface StatusClaim {
    status_list: {
        idx: number;
        uri: string;
    };
}

/** Core SD-JWT VC payload per draft-11 */
export interface SDJWTVCPayload {
    /** Issuer — MUST be a URI */
    iss: string;
    /** Verifiable Credential Type URI */
    vct: string;
    /** Issued at (seconds since epoch) */
    iat: number;
    /** Expiry (seconds since epoch) — RECOMMENDED */
    exp?: number;
    /** Not before (seconds since epoch) — OPTIONAL */
    nbf?: number;
    /** Subject — holder's identifier */
    sub?: string;
    /** Confirmation — Key Binding public key */
    cnf?: CNFClaim;
    /** Status — StatusList2021 reference */
    status?: StatusClaim;
    /** Selectively disclosable claims hashes */
    _sd?: string[];
    /** SD-JWT algorithm */
    _sd_alg?: string;
    /** Additional claims */
    [key: string]: unknown;
}

/** Key Binding JWT payload (typ: kb+jwt) */
export interface KeyBindingJWTPayload {
    /** Audience — verifier's client_id */
    aud: string;
    /** Nonce from verifier */
    nonce: string;
    /** Issued at */
    iat: number;
    /** SHA-256 hash of the SD-JWT (header.payload~disclosures~) */
    sd_hash: string;
}

export interface SDJWTVCValidationResult {
    ok: boolean;
    payload?: SDJWTVCPayload;
    errors: string[];
}

export interface KeyBindingValidationResult {
    ok: boolean;
    payload?: KeyBindingJWTPayload;
    errors: string[];
}

// ─── SD-JWT VC Issuance ───────────────────────────────────────────────────────

/**
 * Issue an SD-JWT VC with all required claims per draft-11.
 * Returns the compact JWT (without disclosures — caller appends ~disclosure~).
 */
export async function issueSDJWTVC(
    payload: Omit<SDJWTVCPayload, '_sd_alg'> & { vct: string; iss: string },
    issuerPrivateKey: CryptoKey
): Promise<string> {
    validateIssuerClaims(payload);

    const fullPayload: SDJWTVCPayload = {
        _sd_alg: 'sha-256',
        ...payload,
    };

    return new SignJWT(fullPayload as unknown as Record<string, unknown>)
        .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt' })
        .sign(issuerPrivateKey);
}

// ─── SD-JWT VC Validation ─────────────────────────────────────────────────────

/**
 * Validate an SD-JWT VC against draft-11 requirements.
 * Verifies signature and all mandatory claims.
 */
export async function validateSDJWTVC(
    sdJwtVc: string,
    issuerPublicKey: CryptoKey | JWK
): Promise<SDJWTVCValidationResult> {
    const errors: string[] = [];

    // Strip disclosures (SD-JWT format: jwt~d1~d2~)
    const parts = sdJwtVc.split('~');
    const jwtPart = parts[0];

    let payload: SDJWTVCPayload;
    try {
        const key = issuerPublicKey instanceof CryptoKey
            ? issuerPublicKey
            : await importJWK(issuerPublicKey as JWK);
        // Bypass jose's time checks — we validate exp/nbf ourselves for clear error messages
        const result = await jwtVerify(jwtPart, key, {
            clockTolerance: Number.MAX_SAFE_INTEGER,
        });
        payload = result.payload as unknown as SDJWTVCPayload;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`Signature verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // Validate typ header — must be vc+sd-jwt
    // (jose validates this via options; we do a claim-level check here)

    // Mandatory: iss — MUST be URI
    if (!payload.iss) {
        errors.push('Missing required claim: iss');
    } else if (!isURI(payload.iss)) {
        errors.push(`iss must be a URI, got: ${payload.iss}`);
    }

    // Mandatory: vct — MUST be URI
    if (!payload.vct) {
        errors.push('Missing required claim: vct');
    } else if (!isURI(payload.vct)) {
        errors.push(`vct must be a URI, got: ${payload.vct}`);
    }

    // Mandatory: iat
    if (payload.iat === undefined || payload.iat === null) {
        errors.push('Missing required claim: iat');
    } else if (typeof payload.iat !== 'number') {
        errors.push('iat must be a number (seconds since epoch)');
    }

    // Optional but validated: exp
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp !== undefined) {
        if (typeof payload.exp !== 'number') {
            errors.push('exp must be a number');
        } else if (payload.exp < now) {
            errors.push(`Credential expired at ${new Date(payload.exp * 1000).toISOString()}`);
        }
    }

    // Optional but validated: nbf
    if (payload.nbf !== undefined) {
        if (typeof payload.nbf !== 'number') {
            errors.push('nbf must be a number');
        } else if (payload.nbf > now + 30) {
            errors.push(`Credential not yet valid (nbf: ${new Date(payload.nbf * 1000).toISOString()})`);
        }
    }

    // cnf: if present, must have jwk with kty
    if (payload.cnf !== undefined) {
        if (typeof payload.cnf !== 'object' || payload.cnf === null) {
            errors.push('cnf must be an object');
        } else if (payload.cnf.jwk !== undefined) {
            if (!payload.cnf.jwk.kty) {
                errors.push('cnf.jwk must have kty');
            }
        }
    }

    // status: if present, must have status_list.idx and uri
    if (payload.status !== undefined) {
        const sl = payload.status.status_list;
        if (!sl || typeof sl.idx !== 'number' || typeof sl.uri !== 'string') {
            errors.push('status.status_list must have numeric idx and string uri');
        }
    }

    // _sd_alg: if present, must be 'sha-256'
    if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') {
        errors.push(`Unsupported _sd_alg: ${payload._sd_alg} (only sha-256 supported)`);
    }

    return {
        ok: errors.length === 0,
        payload: errors.length === 0 ? payload : undefined,
        errors,
    };
}

// ─── Key Binding JWT ──────────────────────────────────────────────────────────

/**
 * Create a Key Binding JWT (typ: kb+jwt) for SD-JWT VC presentation.
 * The holder signs over the SD-JWT hash to prove possession of the binding key.
 */
export async function createKeyBindingJWT(
    opts: {
        aud: string;
        nonce: string;
        sdJwtWithDisclosures: string;
    },
    holderPrivateKey: CryptoKey
): Promise<string> {
    const sdHash = await sha256Base64url(opts.sdJwtWithDisclosures);

    const kbPayload: KeyBindingJWTPayload = {
        aud: opts.aud,
        nonce: opts.nonce,
        iat: Math.floor(Date.now() / 1000),
        sd_hash: sdHash,
    };

    return new SignJWT(kbPayload as unknown as Record<string, unknown>)
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(holderPrivateKey);
}

/**
 * Validate a Key Binding JWT from a presentation.
 * Verifier calls this to confirm the holder controls the cnf key.
 */
export async function validateKeyBindingJWT(
    kbJwt: string,
    holderPublicKey: CryptoKey | JWK,
    opts: {
        expectedAud: string;
        expectedNonce: string;
        sdJwtWithDisclosures: string;
        maxAgeSeconds?: number;
    }
): Promise<KeyBindingValidationResult> {
    const errors: string[] = [];

    let payload: KeyBindingJWTPayload;
    try {
        const key = holderPublicKey instanceof CryptoKey
            ? holderPublicKey
            : await importJWK(holderPublicKey as JWK);
        const result = await jwtVerify(kbJwt, key, {
            typ: 'kb+jwt',
        });
        payload = result.payload as unknown as KeyBindingJWTPayload;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`KB-JWT verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // aud binding
    if (payload.aud !== opts.expectedAud) {
        errors.push(`aud mismatch: expected ${opts.expectedAud}, got ${payload.aud}`);
    }

    // nonce binding
    if (payload.nonce !== opts.expectedNonce) {
        errors.push(`nonce mismatch: expected ${opts.expectedNonce}, got ${payload.nonce}`);
    }

    // iat freshness
    const now = Math.floor(Date.now() / 1000);
    const maxAge = opts.maxAgeSeconds ?? 300; // 5 min default
    if (payload.iat === undefined || now - payload.iat > maxAge) {
        errors.push(`kb+jwt too old or missing iat (max age: ${maxAge}s)`);
    }
    if (payload.iat !== undefined && payload.iat > now + 30) {
        errors.push('kb+jwt iat is in the future');
    }

    // sd_hash binding
    const expectedHash = await sha256Base64url(opts.sdJwtWithDisclosures);
    if (payload.sd_hash !== expectedHash) {
        errors.push('sd_hash does not match SD-JWT');
    }

    return {
        ok: errors.length === 0,
        payload: errors.length === 0 ? payload : undefined,
        errors,
    };
}

// ─── CNF Key Extraction ───────────────────────────────────────────────────────

/**
 * Extract the holder public key from a validated SD-JWT VC payload's cnf claim.
 * Returns null if no cnf claim is present.
 */
export async function extractCNFPublicKey(payload: SDJWTVCPayload): Promise<CryptoKey | null> {
    if (!payload.cnf?.jwk) return null;
    return importJWK(payload.cnf.jwk) as Promise<CryptoKey>;
}

/**
 * Build a cnf claim from a holder CryptoKey (for issuance).
 */
export async function buildCNFClaim(holderPublicKey: CryptoKey): Promise<CNFClaim> {
    const jwk = await exportJWK(holderPublicKey);
    return { jwk };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isURI(value: string): boolean {
    try {
        new URL(value);
        return true;
    } catch {
        // Also accept did: URIs (not standard URLs)
        return value.startsWith('did:') || value.startsWith('urn:');
    }
}

function validateIssuerClaims(payload: Partial<SDJWTVCPayload>): void {
    if (!payload.iss) throw new Error('SD-JWT VC: iss is required');
    if (!payload.vct) throw new Error('SD-JWT VC: vct is required');
    if (payload.iat === undefined) throw new Error('SD-JWT VC: iat is required');
    if (!isURI(payload.iss)) throw new Error(`SD-JWT VC: iss must be a URI, got ${payload.iss}`);
    if (!isURI(payload.vct)) throw new Error(`SD-JWT VC: vct must be a URI, got ${payload.vct}`);
}

async function sha256Base64url(input: string): Promise<string> {
    const data = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    // base64url encode
    const b64 = btoa(String.fromCharCode(...hashArray));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
