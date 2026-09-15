import { describe, it, expect } from 'vitest';
import {
    buildOID4VPRequest,
    SCENARIO_PRESENTATION_DEFINITIONS,
    SCENARIO_LABELS
} from '../demo-flow';

describe('buildOID4VPRequest', () => {
    const defaultOpts = {
        verifierClientId: 'did:mitch:verifier',
        redirectUri: 'https://verifier.example.com/callback',
        scenarioId: 'liquor-store',
    };

    it('successfully builds a request for a valid scenario', () => {
        const result = buildOID4VPRequest(defaultOpts);

        expect(result.nonce).toBeDefined();
        expect(result.nonce).toHaveLength(32); // 16 bytes hex
        expect(result.request).toBeDefined();
        expect(result.request.nonce).toBe(result.nonce);
        expect(result.request.response_type).toBe('vp_token');
        expect(result.request.client_id).toBe(defaultOpts.verifierClientId);
        expect(result.request.redirect_uri).toBe(defaultOpts.redirectUri);
        expect(result.request.response_mode).toBe('direct_post');
        expect(result.request.state).toHaveLength(16); // 8 bytes hex
        expect(result.request.presentation_definition).toEqual(SCENARIO_PRESENTATION_DEFINITIONS['liquor-store']);
        expect(result.request.client_metadata?.client_name).toBe(SCENARIO_LABELS['liquor-store']);
    });

    it('throws an error for an unknown scenario', () => {
        const opts = { ...defaultOpts, scenarioId: 'invalid-scenario' };
        expect(() => buildOID4VPRequest(opts)).toThrow('Unknown scenario: invalid-scenario');
    });

    it('uses provided clientName over scenario label', () => {
        const opts = { ...defaultOpts, clientName: 'Custom Client Name' };
        const result = buildOID4VPRequest(opts);
        expect(result.request.client_metadata?.client_name).toBe('Custom Client Name');
    });

    it('generates unique nonce and state on each call', () => {
        const res1 = buildOID4VPRequest(defaultOpts);
        const res2 = buildOID4VPRequest(defaultOpts);

        expect(res1.nonce).not.toBe(res2.nonce);
        expect(res1.request.state).not.toBe(res2.request.state);
    });

    it('works for all defined scenarios', () => {
        for (const scenarioId of Object.keys(SCENARIO_PRESENTATION_DEFINITIONS)) {
            const result = buildOID4VPRequest({ ...defaultOpts, scenarioId });
            expect(result.request.presentation_definition).toEqual(SCENARIO_PRESENTATION_DEFINITIONS[scenarioId]);
        }
    });
});
