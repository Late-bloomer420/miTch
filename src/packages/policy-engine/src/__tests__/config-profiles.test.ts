import { describe, it, expect } from 'vitest';
import { getConfig, buildConfig, validateConfig, isManifestCompatible, CONFIG_PROFILES } from '../config-profiles';
import type { PolicyManifest } from '@mitch/shared-types';

describe('CONFIG_PROFILES', () => {
    it('strict profile has allowPrompt=false', () => {
        expect(CONFIG_PROFILES.strict.allowPrompt).toBe(false);
    });

    it('strict profile requires verifier fingerprint', () => {
        expect(CONFIG_PROFILES.strict.requireVerifierFingerprint).toBe(true);
    });

    it('pilot profile is not fail-closed', () => {
        expect(CONFIG_PROFILES.pilot.failClosed).toBe(false);
    });

    it('default profile has balanced did resolver', () => {
        expect(CONFIG_PROFILES.default.didResolverProfile).toBe('balanced');
    });
});

describe('getConfig', () => {
    it('returns copy (not reference)', () => {
        const c1 = getConfig('default');
        const c2 = getConfig('default');
        c1.requireWebAuthn = true;
        expect(c2.requireWebAuthn).toBe(false);
    });

    it('defaults to default profile', () => {
        const c = getConfig();
        expect(c.profile).toBe('default');
    });
});

describe('buildConfig', () => {
    it('applies overrides to base profile', () => {
        const c = buildConfig('default', { requireWebAuthn: true });
        expect(c.requireWebAuthn).toBe(true);
        expect(c.profile).toBe('default');
    });
});

describe('validateConfig', () => {
    it('valid default config passes', () => {
        const r = validateConfig(getConfig('default'));
        expect(r.valid).toBe(true);
        expect(r.errors).toHaveLength(0);
    });

    it('strict config is valid', () => {
        const r = validateConfig(getConfig('strict'));
        expect(r.valid).toBe(true);
    });

    it('detects invalid: allowPrompt=false with failClosed=false', () => {
        const c = buildConfig('default', { allowPrompt: false, failClosed: false });
        const r = validateConfig(c);
        expect(r.valid).toBe(false);
        expect(r.errors.some(e => e.includes('allowPrompt=false'))).toBe(true);
    });

    it('detects invalid: requireVerifierFingerprint without requireExplicitRule', () => {
        const c = buildConfig('default', { requireVerifierFingerprint: true, requireExplicitRule: false });
        const r = validateConfig(c);
        expect(r.valid).toBe(false);
    });
});

describe('isManifestCompatible', () => {
    const manifest: PolicyManifest = {
        version: 'v1',
        manifestId: 'test-manifest',
        rules: [],
        manifest_version: 1,
        manifest_hash: 'a'.repeat(64),
    };

    it('strict profile rejects manifest without version', () => {
        const { manifest_version, ...noVersion } = manifest;
        const result = isManifestCompatible(noVersion as PolicyManifest, getConfig('strict'));
        expect(result).toBe(false);
    });

    it('default profile accepts manifest without version', () => {
        const { manifest_version, ...noVersion } = manifest;
        const result = isManifestCompatible(noVersion as PolicyManifest, getConfig('default'));
        expect(result).toBe(true);
    });

    it('strict profile accepts manifest with version', () => {
        const result = isManifestCompatible(manifest, getConfig('strict'));
        expect(result).toBe(true);
    });
});
