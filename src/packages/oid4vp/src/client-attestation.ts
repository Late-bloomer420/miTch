/**
 * OAuth 2.0 Attestation-Based Client Authentication
 * https://drafts.oauth.net/oauth-attestation-based-client-auth/
 *
 * Implements:
 * - Client Attestation JWT (issued by wallet provider/trust anchor)
 * - Client Attestation PoP JWT (proof of possession, per-request)
 * - Verifier-side validation of the full attestation chain
 * - Integration with OID4VP request flow
 */

import { SignJWT, jwtVerify, exportJWK, importJWK } from 'jose';
import type { JWK } from 'jose';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ClientAttestationPayload {
    /** Issuer = wallet provider / trust anchor DID or URI */
    iss: string;
    /** Subject = client_id of the wallet app */
    sub: string;
    /** Issued at */
    iat: number;
    /** Expiry */
    exp: number;
    /** Confirmation: wallet app's public key */
    cnf: { jwk: JWK };
    /** Wallet name (OPTIONAL, informational) */
    wallet_name?: string;
}

export interface ClientAttestationPoPPayload {
    /** Issuer = client_id (same as sub in attestation) */
    iss: string;
    /** Audience = AS/verifier endpoint */
    aud: string;
    /** Issued at */
    iat: number;
    /** Expiry */
    exp: number;
    /** Unique JWT ID (anti-replay) */
    jti: string;
    /** Nonce from verifier (OPTIONAL) */
    nonce?: string;
}

export interface AttestationChain {
    /** Client Attestation JWT (from wallet provider) */
    clientAttestation: string;
    /** Client Attestation PoP JWT (wallet-signed, per request) */
    clientAttestationPoP: string;
}

export interface AttestationValidationResult {
    ok: boolean;
    clientId?: string;
    walletPublicKey?: CryptoKey;
    popPayload?: ClientAttestationPoPPayload;
    errors: string[];
}

// ─── Attestation Issuance (Wallet Provider / Trust Anchor) ────────────────────

/**
 * Issue a Client Attestation JWT.
 * Called by the wallet provider / trust anchor — NOT the wallet itself.
 */
export async function issueClientAttestation(
    opts: {
        iss: string;
        clientId: string;
        walletPublicKey: CryptoKey;
        walletName?: string;
        validitySeconds?: number;
    },
    providerPrivateKey: CryptoKey
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const walletJWK = await exportJWK(opts.walletPublicKey);
    delete walletJWK.d;

    const payload: ClientAttestationPayload = {
        iss: opts.iss,
        sub: opts.clientId,
        iat: now,
        exp: now + (opts.validitySeconds ?? 86400), // 24h default
        cnf: { jwk: walletJWK },
    };
    if (opts.walletName) payload.wallet_name = opts.walletName;

    return new SignJWT(payload as unknown as Record<string, unknown>)
        .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation+jwt' })
        .sign(providerPrivateKey);
}

// ─── PoP JWT Creation (Wallet) ────────────────────────────────────────────────

/**
 * Create a Client Attestation PoP JWT.
 * Called by the wallet for each authorization request to prove key possession.
 */
export async function createClientAttestationPoP(
    opts: {
        clientId: string;
        audience: string;
        nonce?: string;
        validitySeconds?: number;
    },
    walletPrivateKey: CryptoKey
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const payload: ClientAttestationPoPPayload = {
        iss: opts.clientId,
        aud: opts.audience,
        iat: now,
        exp: now + (opts.validitySeconds ?? 60), // 60s default per spec
        jti: generateJTI(),
    };
    if (opts.nonce) payload.nonce = opts.nonce;

    return new SignJWT(payload as unknown as Record<string, unknown>)
        .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
        .sign(walletPrivateKey);
}

// ─── Chain Validation (Verifier / AS) ────────────────────────────────────────

/**
 * Validate the full Client Attestation chain:
 * 1. Verify Client Attestation JWT against trusted provider key
 * 2. Verify Client Attestation PoP JWT against the cnf key from the Attestation
 * 3. Check aud, jti uniqueness, freshness
 */
export async function validateClientAttestationChain(
    chain: AttestationChain,
    opts: {
        expectedAudience: string;
        expectedNonce?: string;
        providerPublicKey: CryptoKey | JWK;
        seenJtis?: Set<string>;
    }
): Promise<AttestationValidationResult> {
    const errors: string[] = [];

    // ── Step 1: Verify Client Attestation JWT ─────────────────────────────────

    let attestationPayload: ClientAttestationPayload;
    let walletPublicKey: CryptoKey;

    try {
        const providerKey = opts.providerPublicKey instanceof CryptoKey
            ? opts.providerPublicKey
            : await importJWK(opts.providerPublicKey) as CryptoKey;

        const result = await jwtVerify(chain.clientAttestation, providerKey, {
            typ: 'oauth-client-attestation+jwt',
            clockTolerance: 30,
        });
        attestationPayload = result.payload as unknown as ClientAttestationPayload;

        if (!attestationPayload.cnf?.jwk) {
            return { ok: false, errors: ['Client Attestation missing cnf.jwk'] };
        }
        walletPublicKey = await importJWK(attestationPayload.cnf.jwk) as CryptoKey;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`Client Attestation verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // Check attestation expiry
    const now = Math.floor(Date.now() / 1000);
    if (attestationPayload.exp < now) {
        errors.push(`Client Attestation expired at ${new Date(attestationPayload.exp * 1000).toISOString()}`);
    }

    // ── Step 2: Verify PoP JWT against wallet's cnf key ───────────────────────

    let popPayload: ClientAttestationPoPPayload;

    try {
        const result = await jwtVerify(chain.clientAttestationPoP, walletPublicKey, {
            typ: 'oauth-client-attestation-pop+jwt',
            clockTolerance: 30,
        });
        popPayload = result.payload as unknown as ClientAttestationPoPPayload;
    } catch (e: unknown) {
        return {
            ok: false,
            errors: [`Client Attestation PoP verification failed: ${e instanceof Error ? e.message : String(e)}`],
        };
    }

    // ── Step 3: Semantic checks ────────────────────────────────────────────────

    // iss in PoP must match sub in Attestation (same client_id)
    if (popPayload.iss !== attestationPayload.sub) {
        errors.push(`PoP iss (${popPayload.iss}) ≠ Attestation sub (${attestationPayload.sub})`);
    }

    // aud binding
    if (popPayload.aud !== opts.expectedAudience) {
        errors.push(`PoP aud mismatch: expected ${opts.expectedAudience}, got ${popPayload.aud}`);
    }

    // nonce binding (if required)
    if (opts.expectedNonce !== undefined) {
        if (!popPayload.nonce) {
            errors.push('PoP missing nonce — verifier requires nonce');
        } else if (popPayload.nonce !== opts.expectedNonce) {
            errors.push(`PoP nonce mismatch: expected ${opts.expectedNonce}`);
        }
    }

    // jti replay check
    if (!popPayload.jti) {
        errors.push('PoP missing jti');
    } else if (opts.seenJtis?.has(popPayload.jti)) {
        errors.push(`Replay detected: jti ${popPayload.jti} already used`);
    } else if (opts.seenJtis) {
        opts.seenJtis.add(popPayload.jti);
    }

    // PoP freshness
    if (popPayload.exp < now) {
        errors.push('Client Attestation PoP expired');
    }
    if (popPayload.iat > now + 30) {
        errors.push('Client Attestation PoP iat in the future');
    }

    return {
        ok: errors.length === 0,
        clientId: errors.length === 0 ? attestationPayload.sub : undefined,
        walletPublicKey: errors.length === 0 ? walletPublicKey : undefined,
        popPayload: errors.length === 0 ? popPayload : undefined,
        errors,
    };
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function generateJTI(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
