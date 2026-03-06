/**
 * DPoP — Demonstrating Proof-of-Possession (RFC 9449)
 * https://www.rfc-editor.org/rfc/rfc9449
 *
 * Implements:
 * - DPoP proof JWT generation (typ=dpop+jwt, alg=ES256, embedded JWK)
 * - DPoP proof validation (htm, htu, iat, jti, nonce binding)
 * - Token-endpoint integration (DPoP-bound access tokens)
 * - Server nonce handling (DPoP-Nonce header flow)
 */

import { SignJWT, jwtVerify, importJWK, exportJWK } from 'jose';
import type { JWK } from 'jose';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DPoPProofHeader {
    typ: 'dpop+jwt';
    alg: 'ES256';
    /** Embedded public key — MUST NOT be private */
    jwk: JWK;
}

export interface DPoPProofPayload {
    /** Unique JWT ID — for replay detection */
    jti: string;
    /** HTTP method (uppercase: GET, POST, …) */
    htm: string;
    /** HTTP target URI (without query/fragment) */
    htu: string;
    /** Issued at (seconds since epoch) */
    iat: number;
    /** Access token hash (base64url SHA-256 of AT) — REQUIRED when AT is present */
    ath?: string;
    /** Server-issued nonce */
    nonce?: string;
}

export interface DPoPProofValidationOptions {
    /** Expected HTTP method (uppercase) */
    expectedHtm: string;
    /** Expected HTTP target URI */
    expectedHtu: string;
    /** Access token (raw, for ath binding check) */
    accessToken?: string;
    /** Server nonce (if nonce-flow active) */
    expectedNonce?: string;
    /** Max age in seconds for iat (default: 60) */
    maxAgeSeconds?: number;
    /** Already-seen JTIs for replay detection */
    seenJtis?: Set<string>;
}

export interface DPoPValidationResult {
    ok: boolean;
    payload?: DPoPProofPayload;
    publicKey?: CryptoKey;
    errors: string[];
}

export interface DPoPKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJWK: JWK;
}

// ─── Key Generation ───────────────────────────────────────────────────────────

/** Generate a fresh DPoP key pair (ES256) for use in proofs. */
export async function generateDPoPKeyPair(): Promise<DPoPKeyPair> {
    const pair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
    const publicKeyJWK = await exportJWK(pair.publicKey);
    // Ensure no private key material in embedded JWK
    delete publicKeyJWK.d;
    return {
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
        publicKeyJWK,
    };
}

// ─── Proof Generation ─────────────────────────────────────────────────────────

/**
 * Generate a DPoP proof JWT per RFC 9449 §4.2.
 * The proof binds the request to a specific HTTP method + URI.
 *
 * @param opts.htm  HTTP method (e.g. "POST")
 * @param opts.htu  HTTP target URI (e.g. "https://as.example.com/token")
 * @param opts.nonce  Server-issued nonce (from DPoP-Nonce header)
 * @param opts.accessToken  If bound to an AT, include ath claim
 */
export async function createDPoPProof(
    opts: {
        htm: string;
        htu: string;
        nonce?: string;
        accessToken?: string;
    },
    keyPair: DPoPKeyPair
): Promise<string> {
    const jti = generateJTI();
    const iat = Math.floor(Date.now() / 1000);

    const payload: DPoPProofPayload = {
        jti,
        htm: opts.htm.toUpperCase(),
        htu: normalizeHtu(opts.htu),
        iat,
    };

    if (opts.nonce) {
        payload.nonce = opts.nonce;
    }

    if (opts.accessToken) {
        payload.ath = await sha256Base64url(opts.accessToken);
    }

    const publicJwk = { ...keyPair.publicKeyJWK };
    delete publicJwk.d; // paranoia — never embed private key

    return new SignJWT(payload as unknown as Record<string, unknown>)
        .setProtectedHeader({
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: publicJwk,
        })
        .sign(keyPair.privateKey);
}

// ─── Proof Validation ─────────────────────────────────────────────────────────

/**
 * Validate a DPoP proof JWT per RFC 9449 §4.3.
 * Used by resource servers and authorization endpoints.
 */
export async function validateDPoPProof(
    proofJwt: string,
    opts: DPoPProofValidationOptions
): Promise<DPoPValidationResult> {
    const errors: string[] = [];

    // 1. Decode header to extract embedded JWK (before signature check)
    let embeddedJWK: JWK;
    let publicKey: CryptoKey;
    try {
        const headerB64 = proofJwt.split('.')[0];
        const header = JSON.parse(
            atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'))
        ) as DPoPProofHeader;

        if (header.typ !== 'dpop+jwt') {
            return { ok: false, errors: ['typ must be dpop+jwt'] };
        }
        if (!header.jwk) {
            return { ok: false, errors: ['Missing jwk in header'] };
        }
        if ((header.jwk as unknown as Record<string, unknown>).d) {
            return { ok: false, errors: ['jwk must not contain private key material (d)'] };
        }

        embeddedJWK = header.jwk;
        publicKey = await importJWK(embeddedJWK) as CryptoKey;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`Header parse/key import failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // 2. Verify signature using embedded key
    let payload: DPoPProofPayload;
    try {
        const result = await jwtVerify(proofJwt, publicKey, {
            typ: 'dpop+jwt',
            clockTolerance: 30, // 30s clock skew tolerance
        });
        payload = result.payload as unknown as DPoPProofPayload;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`Signature verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // 3. jti — MUST be unique (replay detection)
    if (!payload.jti) {
        errors.push('Missing jti claim');
    } else if (opts.seenJtis?.has(payload.jti)) {
        errors.push(`Replay detected: jti ${payload.jti} already used`);
    }

    // 4. htm — HTTP method binding
    if (!payload.htm) {
        errors.push('Missing htm claim');
    } else if (payload.htm !== opts.expectedHtm.toUpperCase()) {
        errors.push(`htm mismatch: expected ${opts.expectedHtm.toUpperCase()}, got ${payload.htm}`);
    }

    // 5. htu — URI binding (scheme + authority + path, no query/fragment)
    if (!payload.htu) {
        errors.push('Missing htu claim');
    } else if (normalizeHtu(payload.htu) !== normalizeHtu(opts.expectedHtu)) {
        errors.push(`htu mismatch: expected ${normalizeHtu(opts.expectedHtu)}, got ${normalizeHtu(payload.htu)}`);
    }

    // 6. iat freshness
    const now = Math.floor(Date.now() / 1000);
    const maxAge = opts.maxAgeSeconds ?? 60;
    if (payload.iat === undefined) {
        errors.push('Missing iat claim');
    } else if (now - payload.iat > maxAge) {
        errors.push(`DPoP proof too old: age ${now - payload.iat}s > ${maxAge}s`);
    } else if (payload.iat > now + 30) {
        errors.push('DPoP proof iat is in the future');
    }

    // 7. nonce binding (if server uses nonce flow)
    if (opts.expectedNonce !== undefined) {
        if (!payload.nonce) {
            errors.push('Missing nonce — server requires DPoP nonce');
        } else if (payload.nonce !== opts.expectedNonce) {
            errors.push(`nonce mismatch: expected ${opts.expectedNonce}, got ${payload.nonce}`);
        }
    }

    // 8. ath — access token hash binding
    if (opts.accessToken !== undefined) {
        const expectedAth = await sha256Base64url(opts.accessToken);
        if (!payload.ath) {
            errors.push('Missing ath claim — required when access token is present');
        } else if (payload.ath !== expectedAth) {
            errors.push('ath does not match access token hash');
        }
    }

    // Register JTI as seen (caller is responsible for persisting this)
    if (payload.jti && opts.seenJtis) {
        opts.seenJtis.add(payload.jti);
    }

    return {
        ok: errors.length === 0,
        payload: errors.length === 0 ? payload : undefined,
        publicKey: errors.length === 0 ? publicKey : undefined,
        errors,
    };
}

// ─── Token Binding ────────────────────────────────────────────────────────────

/**
 * Compute the DPoP thumbprint of a public key (RFC 9449 §6).
 * Used as the `cnf.jkt` value in DPoP-bound access tokens.
 */
export async function computeDPoPThumbprint(publicKeyJWK: JWK): Promise<string> {
    // JWK Thumbprint per RFC 7638 — sorted, minimal key members
    const requiredMembers = getRequiredJWKMembers(publicKeyJWK);
    const canonical = JSON.stringify(requiredMembers, Object.keys(requiredMembers).sort());
    return sha256Base64url(canonical);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateJTI(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Strip query string and fragment from URI per RFC 9449 §4.2 */
function normalizeHtu(uri: string): string {
    try {
        const url = new URL(uri);
        return `${url.protocol}//${url.host}${url.pathname}`;
    } catch {
        return uri;
    }
}

async function sha256Base64url(input: string): Promise<string> {
    const data = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    const b64 = btoa(String.fromCharCode(...hashArray));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function getRequiredJWKMembers(jwk: JWK): Record<string, unknown> {
    // RFC 7638: required members per kty
    const kty = jwk.kty;
    if (kty === 'EC') {
        return { crv: jwk.crv, kty, x: jwk.x, y: jwk.y };
    } else if (kty === 'RSA') {
        const jwkRaw = jwk as unknown as Record<string, unknown>;
        return { e: jwkRaw['e'], kty, n: jwkRaw['n'] };
    }
    return { kty };
}
