import { describe, it, expect } from 'vitest';
import { DenialResolver } from '../catalog';
import { ReasonCode } from '../engine';

describe('DenialResolver.resolve() — catalog coverage', () => {
    it('CREDENTIAL_EXPIRED maps to FRESHNESS_EXPIRED entry', () => {
        const result = DenialResolver.resolve(ReasonCode.CREDENTIAL_EXPIRED);
        expect(result.reasonCode).toBe('FRESHNESS_EXPIRED');
        expect(result.title).toBeTruthy();
        expect(result.message).toBeTruthy();
        expect(result.severity).toBe('WARN');
    });

    it('CREDENTIAL_TOO_OLD also maps to FRESHNESS_EXPIRED', () => {
        const result = DenialResolver.resolve(ReasonCode.CREDENTIAL_TOO_OLD);
        expect(result.reasonCode).toBe('FRESHNESS_EXPIRED');
    });

    it('CLAIM_NOT_ALLOWED maps to ATTRIBUTE_BLOCKED entry', () => {
        const result = DenialResolver.resolve(ReasonCode.CLAIM_NOT_ALLOWED);
        expect(result.reasonCode).toBe('ATTRIBUTE_BLOCKED');
        expect(result.severity).toBe('HIGH');
        expect(result.actions.length).toBeGreaterThan(0);
    });

    it('LAYER_VIOLATION maps to LAYER_VIOLATION entry with CRITICAL severity', () => {
        const result = DenialResolver.resolve(ReasonCode.LAYER_VIOLATION);
        expect(result.reasonCode).toBe('LAYER_VIOLATION');
        expect(result.severity).toBe('CRITICAL');
        expect(result.message).toBeTruthy();
    });

    it('CONSENT_REQUIRED maps to CONSENT_REQUIRED entry', () => {
        const result = DenialResolver.resolve(ReasonCode.CONSENT_REQUIRED);
        expect(result.reasonCode).toBe('CONSENT_REQUIRED');
        expect(result.title).toBeTruthy();
        expect(result.message).toBeTruthy();
    });

    it('NO_SUITABLE_CREDENTIAL has at least one recovery action', () => {
        const result = DenialResolver.resolve(ReasonCode.NO_SUITABLE_CREDENTIAL);
        expect(result.reasonCode).toBe('NO_SUITABLE_CREDENTIAL');
        expect(result.actions.length).toBeGreaterThan(0);
    });

    it('UNTRUSTED_ISSUER exposes issuer name via interpolation', () => {
        const result = DenialResolver.resolve(ReasonCode.UNTRUSTED_ISSUER, { issuer: 'did:example:rogue' });
        expect(result.reasonCode).toBe('UNTRUSTED_ISSUER');
        expect(result.message).toContain('did:example:rogue');
    });

    it('UNKNOWN_VERIFIER exposes verifierId via interpolation', () => {
        const result = DenialResolver.resolve(ReasonCode.UNKNOWN_VERIFIER, { verifierId: 'did:example:evil' });
        expect(result.reasonCode).toBe('UNKNOWN_VERIFIER');
        expect(result.message).toContain('did:example:evil');
    });

    it('unknown reason code falls back to NO_MATCHING_RULE entry', () => {
        const result = DenialResolver.resolve('COMPLETELY_UNKNOWN_CODE');
        expect(result.reasonCode).toBe('NO_MATCHING_RULE');
    });

    it('missing interpolation variable renders as ?', () => {
        const result = DenialResolver.resolve(ReasonCode.UNKNOWN_VERIFIER, {});
        expect(result.message).toContain('?');
    });

    it('all catalog entries have non-empty title and message', () => {
        const codes = [
            ReasonCode.UNKNOWN_VERIFIER,
            ReasonCode.NO_SUITABLE_CREDENTIAL,
            ReasonCode.CLAIM_NOT_ALLOWED,
            ReasonCode.LAYER_VIOLATION,
            ReasonCode.CREDENTIAL_EXPIRED,
            ReasonCode.NO_MATCHING_RULE,
            ReasonCode.CONSENT_REQUIRED,
            ReasonCode.UNTRUSTED_ISSUER,
        ];

        for (const code of codes) {
            const result = DenialResolver.resolve(code);
            expect(result.title, `title for ${code}`).toBeTruthy();
            expect(result.message, `message for ${code}`).toBeTruthy();
        }
    });

    it('all catalog entries have a learnMoreUrl or actions (or both)', () => {
        const codes = [
            ReasonCode.UNKNOWN_VERIFIER,
            ReasonCode.NO_SUITABLE_CREDENTIAL,
            ReasonCode.LAYER_VIOLATION,
            ReasonCode.CREDENTIAL_EXPIRED,
            ReasonCode.UNTRUSTED_ISSUER,
        ];

        for (const code of codes) {
            const result = DenialResolver.resolve(code);
            const hasUrl = !!result.learnMoreUrl;
            const hasActions = result.actions.length > 0;
            expect(hasUrl || hasActions, `${code} should have learnMoreUrl or actions`).toBe(true);
        }
    });
});
