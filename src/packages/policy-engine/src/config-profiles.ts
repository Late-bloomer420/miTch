/**
 * Config Profiles for Policy Engine (Specs 32, 42, 76, 83)
 *
 * Default (balanced), Strict (Spec 76), Pilot/Demo (Spec 42),
 * DID Resolver profile (Spec 83).
 */

import type { PolicyManifest } from '@mitch/shared-types';

// ─── Profile Types ─────────────────────────────────────────────────

export type PolicyProfile = 'default' | 'strict' | 'pilot' | 'minimal';

export interface PolicyEngineConfig {
    profile: PolicyProfile;
    /** Fail closed on evaluation error (default: true) */
    failClosed: boolean;
    /** Allow PROMPT verdict (false = convert PROMPT to DENY) */
    allowPrompt: boolean;
    /** Max evaluation time in ms before fail-closed (default: 2000) */
    evaluationTimeoutMs: number;
    /** Require verifier fingerprint for all ALLOW verdicts */
    requireVerifierFingerprint: boolean;
    /** Enable pairwise DID generation */
    enablePairwiseDID: boolean;
    /** Require explicit policy rule match (no default ALLOW) */
    requireExplicitRule: boolean;
    /** WebAuthn required for critical operations */
    requireWebAuthn: boolean;
    /** DID resolver profile (Spec 83) */
    didResolverProfile: 'permissive' | 'balanced' | 'strict';
    /** Rate limit: max requests per verifier per hour */
    rateLimitPerVerifierPerHour: number;
    /** Max proof fatigue prompts per 10min */
    maxProofPromptsPerWindow: number;
}

// ─── Profile Definitions ───────────────────────────────────────────

export const CONFIG_PROFILES: Record<PolicyProfile, PolicyEngineConfig> = {
    /** Balanced: secure defaults, allows PROMPT */
    default: {
        profile: 'default',
        failClosed: true,
        allowPrompt: true,
        evaluationTimeoutMs: 2000,
        requireVerifierFingerprint: false,
        enablePairwiseDID: true,
        requireExplicitRule: true,
        requireWebAuthn: false,
        didResolverProfile: 'balanced',
        rateLimitPerVerifierPerHour: 1000,
        maxProofPromptsPerWindow: 5,
    },
    /** Strict (Spec 76): everything DENY on doubt, no PROMPT */
    strict: {
        profile: 'strict',
        failClosed: true,
        allowPrompt: false, // PROMPT → DENY
        evaluationTimeoutMs: 1000,
        requireVerifierFingerprint: true,
        enablePairwiseDID: true,
        requireExplicitRule: true,
        requireWebAuthn: true,
        didResolverProfile: 'strict',
        rateLimitPerVerifierPerHour: 100,
        maxProofPromptsPerWindow: 2,
    },
    /** Pilot/Demo (Spec 42): relaxed for demonstrations */
    pilot: {
        profile: 'pilot',
        failClosed: false, // Allow graceful degradation in demo
        allowPrompt: true,
        evaluationTimeoutMs: 5000,
        requireVerifierFingerprint: false,
        enablePairwiseDID: true,
        requireExplicitRule: false, // Demo: allow without explicit rule
        requireWebAuthn: false,
        didResolverProfile: 'permissive',
        rateLimitPerVerifierPerHour: 10000,
        maxProofPromptsPerWindow: 20,
    },
    /** Minimal: for unit tests and CI only */
    minimal: {
        profile: 'minimal',
        failClosed: true,
        allowPrompt: true,
        evaluationTimeoutMs: 30000,
        requireVerifierFingerprint: false,
        enablePairwiseDID: false,
        requireExplicitRule: true,
        requireWebAuthn: false,
        didResolverProfile: 'permissive',
        rateLimitPerVerifierPerHour: 999999,
        maxProofPromptsPerWindow: 999,
    },
};

// ─── Config Builder ────────────────────────────────────────────────

/**
 * Get a policy engine configuration by profile name.
 */
export function getConfig(profile: PolicyProfile = 'default'): PolicyEngineConfig {
    return { ...CONFIG_PROFILES[profile] };
}

/**
 * Merge overrides onto a base profile.
 */
export function buildConfig(profile: PolicyProfile, overrides: Partial<PolicyEngineConfig> = {}): PolicyEngineConfig {
    return { ...CONFIG_PROFILES[profile], ...overrides, profile };
}

/**
 * Validate a config object for internal consistency.
 */
export function validateConfig(config: PolicyEngineConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.allowPrompt && !config.failClosed) {
        errors.push('Invalid: allowPrompt=false requires failClosed=true');
    }

    if (config.requireVerifierFingerprint && !config.requireExplicitRule) {
        errors.push('Invalid: requireVerifierFingerprint requires requireExplicitRule=true');
    }

    if (config.evaluationTimeoutMs <= 0) {
        errors.push('Invalid: evaluationTimeoutMs must be positive');
    }

    if (config.rateLimitPerVerifierPerHour <= 0) {
        errors.push('Invalid: rateLimitPerVerifierPerHour must be positive');
    }

    return { valid: errors.length === 0, errors };
}

/**
 * Determine if a manifest is compatible with a given profile.
 */
export function isManifestCompatible(manifest: PolicyManifest, config: PolicyEngineConfig): boolean {
    // Strict profile requires manifest_version for rollback protection
    if (config.profile === 'strict' && manifest.manifest_version === undefined) {
        return false;
    }
    return true;
}
