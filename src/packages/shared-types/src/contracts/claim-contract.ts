/**
 * @module @askmi/shared-types/contracts/claim-contract
 *
 * Versioned, EUDI-aligned claim/predicate contract (beachhead: age verification).
 *
 * Single source of truth that ends the cross-layer vocabulary drift behind the
 * non-deterministic AGE_NOT_VERIFIED failure (G-100.1). Internal call-sites use
 * the deprecated aliases (`age`, `isOver18`, `dateOfBirth`, …); this contract
 * maps them onto the canonical EUDI names and fails closed on anything unknown.
 *
 * Canonical names follow EUDI/OIDC conventions so the pilot speaks the same
 * language as the EU wallet ecosystem from day one:
 *   - `birthdate`    — disclosed attribute, ISO-8601 full-date (OIDC standard claim)
 *   - `age_over_18`  — boolean predicate result (ISO 18013-5 / AV-Profile spelling)
 *
 * See docs/superpowers/specs/2026-06-10-eudi-claim-contract-design.md.
 */

/** Semantic version of this contract. Bump per the design's versioning rules. */
export const CLAIM_CONTRACT_VERSION = '1.0.0' as const;

/** The canonical claim names recognised by contract v1. */
export const CANONICAL_CLAIMS = ['birthdate', 'age_over_18'] as const;

export type CanonicalClaim = (typeof CANONICAL_CLAIMS)[number];

/** Thrown when a claim name is neither canonical nor a known alias (fail-closed). */
export class UnknownClaimError extends Error {
    constructor(public readonly claim: string) {
        super(`UNKNOWN_CLAIM: "${claim}" is not a canonical claim or known alias`);
        this.name = 'UnknownClaimError';
    }
}

/**
 * Deprecated alias → canonical name. Aliases bridge existing internal call-sites
 * onto the EUDI canonical vocabulary; they are never removed within a major
 * version. Unknown names are rejected (no silent default).
 */
const ALIAS_TO_CANONICAL: Readonly<Record<string, CanonicalClaim>> = {
    // → birthdate (disclosed attribute)
    dateOfBirth: 'birthdate',
    birthDate: 'birthdate',
    birth_date: 'birthdate',
    age: 'birthdate',
    // → age_over_18 (predicate result)
    isOver18: 'age_over_18',
    'age >= 18': 'age_over_18',
    over18: 'age_over_18',
    age_gte_18: 'age_over_18',
};

const CANONICAL_SET: ReadonlySet<string> = new Set(CANONICAL_CLAIMS);

/**
 * Resolve any recognised claim name (canonical or deprecated alias) to its
 * canonical form. Fail-closed: throws {@link UnknownClaimError} otherwise.
 */
export function resolveClaim(name: string): CanonicalClaim {
    if (CANONICAL_SET.has(name)) return name as CanonicalClaim;
    const canonical = ALIAS_TO_CANONICAL[name];
    if (canonical) return canonical;
    throw new UnknownClaimError(name);
}

// ── Format bindings ─────────────────────────────────────────────────────────
//
// One logical canonical claim serialises differently per credential format.
// The contract declares each binding so consumers translate at the credential
// edge instead of guessing. AV-Profile bindings are *reserved*: declared and
// asserted here, but not yet wired into a live flow (tracked in issue #97).

/** Credential formats the contract knows how to bind to. */
export type CredentialFormatId = 'sd-jwt-vc' | 'mdoc-pid' | 'av-profile';

/**
 * How a canonical claim is located/encoded inside one credential format.
 * - `value`            — the locator path/element holds the attribute value.
 * - `flat-bool`        — the locator element is a standalone boolean (mdoc).
 * - `nested-threshold` — the locator is `age_equal_or_over.<NN>` (SD-JWT VC).
 */
export interface ClaimFormatBinding {
    format: CredentialFormatId;
    /** SD-JWT VC `vct` / mdoc docType / PID namespace identifier. */
    credentialType: string;
    /** Dot-path (SD-JWT VC) or element identifier (mdoc). */
    locator: string;
    encoding: 'value' | 'flat-bool' | 'nested-threshold';
    /** True = declared EUDI target, not yet wired into a live flow (issue #97). */
    reserved?: boolean;
}

const FORMAT_BINDINGS: Readonly<
    Record<CanonicalClaim, Partial<Record<CredentialFormatId, ClaimFormatBinding>>>
> = {
    age_over_18: {
        'sd-jwt-vc': {
            format: 'sd-jwt-vc',
            credentialType: 'urn:eudi:pid:1',
            locator: 'age_equal_or_over.18',
            encoding: 'nested-threshold',
        },
        'mdoc-pid': {
            format: 'mdoc-pid',
            credentialType: 'eu.europa.ec.eudi.pid.1',
            locator: 'age_over_18',
            encoding: 'flat-bool',
        },
        'av-profile': {
            format: 'av-profile',
            credentialType: 'eu.europa.ec.av.1',
            locator: 'age_over_18',
            encoding: 'flat-bool',
            reserved: true,
        },
    },
    birthdate: {
        'sd-jwt-vc': {
            format: 'sd-jwt-vc',
            credentialType: 'urn:eudi:pid:1',
            locator: 'birthdate',
            encoding: 'value',
        },
        'mdoc-pid': {
            format: 'mdoc-pid',
            credentialType: 'eu.europa.ec.eudi.pid.1',
            locator: 'birth_date',
            encoding: 'value',
        },
        // No `av-profile`: the AV attestation SHALL NOT carry birthdate (minimization).
    },
};

/**
 * Look up how a canonical claim binds to a credential format. Returns
 * `undefined` when the claim is intentionally absent in that format (e.g.
 * `birthdate` in the AV-Profile, which carries no date of birth).
 */
export function getFormatBinding(
    claim: CanonicalClaim,
    format: CredentialFormatId,
): ClaimFormatBinding | undefined {
    return FORMAT_BINDINGS[claim][format];
}
