import { describe, it, expect } from 'vitest';
import { DenialResolver } from '../src/catalog';
import { ReasonCode } from '../src/engine';

describe('T-28: Policy Denial & Recovery (DenialResolver)', () => {

    it('should map UNKNOWN_VERIFIER to critical severity with actions', () => {
        const resolution = DenialResolver.resolve(ReasonCode.UNKNOWN_VERIFIER, { verifierId: 'did:example:evil-corp' });

        expect(resolution.reasonCode).toBe('UNKNOWN_VERIFIER');
        expect(resolution.severity).toBe('CRITICAL');
        expect(resolution.message).toContain('did:example:evil-corp');

        const overrideAction = resolution.actions.find(a => a.type === 'OVERRIDE_WITH_CONSENT');
        expect(overrideAction).toBeDefined();
        expect(overrideAction?.requiresConfirm).toBe(true);
    });

    it('should map NO_SUITABLE_CREDENTIAL to high severity with LOAD_CREDENTIAL action', () => {
        const resolution = DenialResolver.resolve(ReasonCode.NO_SUITABLE_CREDENTIAL);

        expect(resolution.reasonCode).toBe('NO_SUITABLE_CREDENTIAL');
        expect(resolution.severity).toBe('HIGH');

        const loadAction = resolution.actions.find(a => a.type === 'LOAD_CREDENTIAL');
        expect(loadAction).toBeDefined();
        expect(loadAction?.label).toBe('Credential laden');
    });

    it('should perform string interpolation in messages', () => {
        const resolution = DenialResolver.resolve(ReasonCode.UNKNOWN_VERIFIER, { verifierId: 'TargetVerifier' });
        expect(resolution.message).toBe('Dieser Service (TargetVerifier) ist nicht im Register. Fortfahren auf eigenes Risiko.');
    });

    it('should gracefully handle unknown reason codes', () => {
        const resolution = DenialResolver.resolve('RANDOM_ERROR_CODE');
        expect(resolution.reasonCode).toBe('NO_MATCHING_RULE'); // Default fallback
        expect(resolution.title).toBe('Zugriff blockiert');
    });
});
