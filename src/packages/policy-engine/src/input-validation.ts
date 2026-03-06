/**
 * S-03: Input Validation Schema für Policy Parser
 *
 * Whitelist-basierte Validierung aller Claim-Namen und Verifier-IDs
 * die in PolicyManifest und VerifierRequest ankommen.
 *
 * Angriffsmuster: Claim-Name Injection
 * Defense:
 * - Nur alphanumerische Zeichen + Bindestrich/Unterstrich erlaubt
 * - Keine Pfad-Muster (., /, .., \)
 * - Keine Sonderzeichen (*, $, @, ...)
 * - Normalisierung VOR Auswertung: trim + lowercase
 * - Maximale Länge: 128 Zeichen
 */

// ─── Constants ────────────────────────────────────────────────────────────────

/** Maximum allowed length for a single claim name */
const MAX_CLAIM_NAME_LENGTH = 128;

/** Maximum allowed length for a verifier DID */
const MAX_DID_LENGTH = 512;

/** Maximum number of claims per request or rule */
const MAX_CLAIMS_PER_LIST = 50;

/**
 * Whitelist pattern for claim names.
 * Allows: letters (a-z, A-Z), digits (0-9), hyphens (-), underscores (_).
 * Rejects: dots, slashes, colons, wildcards, brackets, etc.
 */
const CLAIM_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_-]{0,127}$/;

/**
 * Whitelist pattern for DID strings.
 * Allows: did:<method>:<identifier> — alphanumeric + limited punctuation.
 * Rejects: path traversal (../, \\), script injection, etc.
 * NOTE: hyphen must be escaped or placed last in character class to avoid range misinterpretation.
 */
const DID_PATTERN = /^did:[a-zA-Z0-9]+:[a-zA-Z0-9._\-:%]{1,400}$/;

/**
 * Wildcard DID pattern (for verifierPattern fields that allow * globbing).
 * The * is only permitted in verifierPattern, not in actual DIDs in requests.
 */
const VERIFIER_PATTERN_PATTERN = /^(\*|did:[a-zA-Z0-9]+:[a-zA-Z0-9._\-:%*]{1,400})$/;

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ClaimValidationResult {
    valid: boolean;
    normalized: string[];
    rejected: Array<{ claim: string; reason: string }>;
}

/**
 * Normalize a single claim name: trim + lowercase.
 * Returns null if the result is empty.
 */
export function normalizeClaimName(raw: string): string | null {
    if (typeof raw !== 'string') return null;
    const normalized = raw.trim().toLowerCase();
    return normalized.length > 0 ? normalized : null;
}

/**
 * Validate and normalize a list of claim names (whitelist-based).
 *
 * - Normalizes each claim (trim + lowercase) before validation
 * - Rejects claims with path patterns, special chars, or excessive length
 * - Returns both the valid normalized list and the rejected items with reasons
 */
export function validateClaimNames(claims: unknown[]): ClaimValidationResult {
    const normalized: string[] = [];
    const rejected: Array<{ claim: string; reason: string }> = [];

    if (!Array.isArray(claims)) {
        return { valid: false, normalized: [], rejected: [{ claim: '<input>', reason: 'Must be an array' }] };
    }

    if (claims.length > MAX_CLAIMS_PER_LIST) {
        return {
            valid: false,
            normalized: [],
            rejected: [{ claim: '<list>', reason: `Too many claims: ${claims.length} > ${MAX_CLAIMS_PER_LIST}` }]
        };
    }

    for (const raw of claims) {
        if (typeof raw !== 'string') {
            rejected.push({ claim: String(raw), reason: 'Not a string' });
            continue;
        }

        const norm = normalizeClaimName(raw);
        if (!norm) {
            rejected.push({ claim: raw, reason: 'Empty after normalization' });
            continue;
        }

        if (norm.length > MAX_CLAIM_NAME_LENGTH) {
            rejected.push({ claim: raw, reason: `Exceeds max length of ${MAX_CLAIM_NAME_LENGTH}` });
            continue;
        }

        if (!CLAIM_NAME_PATTERN.test(norm)) {
            rejected.push({ claim: raw, reason: 'Failed whitelist pattern (only a-z, 0-9, _, - allowed; must start with letter)' });
            continue;
        }

        normalized.push(norm);
    }

    return {
        valid: rejected.length === 0,
        normalized,
        rejected,
    };
}

/**
 * Validate a verifier DID (strict format, no wildcards).
 * Used for VerifierRequest.verifierId.
 */
export function validateVerifierDID(did: unknown): { valid: boolean; reason?: string } {
    if (typeof did !== 'string') return { valid: false, reason: 'Not a string' };
    if (did.length > MAX_DID_LENGTH) return { valid: false, reason: `DID too long (max ${MAX_DID_LENGTH})` };
    if (!DID_PATTERN.test(did)) return { valid: false, reason: 'Invalid DID format' };
    return { valid: true };
}

/**
 * Validate a verifier pattern (may contain * for glob matching).
 * Used for PolicyRule.verifierPattern.
 */
export function validateVerifierPattern(pattern: unknown): { valid: boolean; reason?: string } {
    if (typeof pattern !== 'string') return { valid: false, reason: 'Not a string' };
    if (pattern.length > MAX_DID_LENGTH) return { valid: false, reason: `Pattern too long (max ${MAX_DID_LENGTH})` };
    if (!VERIFIER_PATTERN_PATTERN.test(pattern)) return { valid: false, reason: 'Invalid verifier pattern' };
    return { valid: true };
}

/**
 * Sanitize a complete list of claims from a VerifierRequest.
 * Returns only the claims that pass whitelist validation (normalized).
 * Malformed claims are silently dropped (fail-safe).
 */
export function sanitizeRequestedClaims(claims: unknown): string[] {
    if (!Array.isArray(claims)) return [];
    const result = validateClaimNames(claims);
    return result.normalized;
}
