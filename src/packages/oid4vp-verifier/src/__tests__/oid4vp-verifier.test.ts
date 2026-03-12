import { describe, it, expect } from 'vitest';
import { buildAuthorizationRequest, encodeAuthorizationRequest } from '../request-builder';
import { verifyAuthorizationResponse, satisfiesConstraints } from '../response-verifier';
import type { PresentationDefinition, AuthorizationResponse } from '@mitch/oid4vp';

const DEFINITION: PresentationDefinition = {
    id: 'age-pd',
    input_descriptors: [
        {
            id: 'age-descriptor',
            constraints: {
                limit_disclosure: 'required',
                fields: [{ path: ['$.credentialSubject.over18'] }],
            },
        },
    ],
};

const buildResponse = (overrides: Partial<AuthorizationResponse> = {}): AuthorizationResponse => ({
    vp_token: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig',
    presentation_submission: {
        id: 'sub-1',
        definition_id: 'age-pd',
        descriptor_map: [{ id: 'age-descriptor', format: 'sd-jwt', path: '$' }],
    },
    state: 'state-123',
    ...overrides,
});

describe('buildAuthorizationRequest', () => {
    it('generates unique nonces', () => {
        const r1 = buildAuthorizationRequest({ clientId: 'c', redirectUri: 'r', definition: DEFINITION });
        const r2 = buildAuthorizationRequest({ clientId: 'c', redirectUri: 'r', definition: DEFINITION });
        expect(r1.nonce).not.toBe(r2.nonce);
    });

    it('sets response_type to vp_token', () => {
        const r = buildAuthorizationRequest({ clientId: 'c', redirectUri: 'r', definition: DEFINITION });
        expect(r.response_type).toBe('vp_token');
    });

    it('uses provided response_mode', () => {
        const r = buildAuthorizationRequest({
            clientId: 'c', redirectUri: 'r', definition: DEFINITION, responseMode: 'fragment'
        });
        expect(r.response_mode).toBe('fragment');
    });

    it('defaults to direct_post response_mode', () => {
        const r = buildAuthorizationRequest({ clientId: 'c', redirectUri: 'r', definition: DEFINITION });
        expect(r.response_mode).toBe('direct_post');
    });
});

describe('encodeAuthorizationRequest', () => {
    it('encodes to URL params string', () => {
        const req = buildAuthorizationRequest({ clientId: 'client1', redirectUri: 'https://rp.example', definition: DEFINITION });
        const encoded = encodeAuthorizationRequest(req);
        expect(encoded).toContain('client_id=client1');
        expect(encoded).toContain('response_type=vp_token');
        expect(encoded).toContain('presentation_definition=');
    });
});

describe('verifyAuthorizationResponse', () => {
    it('accepts valid response', () => {
        const response = buildResponse();
        const result = verifyAuthorizationResponse({
            response,
            expectedNonce: 'nonce-valid-1',
            expectedState: 'state-123',
            definition: DEFINITION,
            skipNonceCheck: true,
        });
        expect(result.valid).toBe(true);
        expect(result.credentials).toHaveLength(1);
    });

    it('rejects state mismatch', () => {
        const result = verifyAuthorizationResponse({
            response: buildResponse({ state: 'wrong' }),
            expectedNonce: 'n',
            expectedState: 'state-123',
            definition: DEFINITION,
            skipNonceCheck: true,
        });
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('State mismatch'))).toBe(true);
    });

    it('rejects submission with wrong definition_id', () => {
        const response = buildResponse({
            presentation_submission: {
                id: 'sub-2',
                definition_id: 'wrong-pd',
                descriptor_map: [{ id: 'age-descriptor', format: 'sd-jwt', path: '$' }],
            },
        });
        const result = verifyAuthorizationResponse({
            response,
            expectedNonce: 'n2',
            expectedState: undefined,
            definition: DEFINITION,
            skipNonceCheck: true,
        });
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('mismatch'))).toBe(true);
    });

    it('rejects empty vp_token', () => {
        const result = verifyAuthorizationResponse({
            response: buildResponse({ vp_token: '' }),
            expectedNonce: 'n3',
            definition: DEFINITION,
            skipNonceCheck: true,
        });
        expect(result.valid).toBe(false);
    });
});

describe('satisfiesConstraints', () => {
    it('accepts valid credential', () => {
        const r = satisfiesConstraints('eyJhbGciOiJFUzI1NiJ9.payload.sig', DEFINITION);
        expect(r.ok).toBe(true);
    });

    it('rejects too-short credential', () => {
        const r = satisfiesConstraints('short', DEFINITION);
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('INVALID_CREDENTIAL');
    });

    it('accepts credential with definition containing no fields', () => {
        const emptyDef: PresentationDefinition = {
            id: 'empty-pd',
            input_descriptors: [{ id: 'desc', constraints: { fields: [] } }],
        };
        const r = satisfiesConstraints('eyJhbGciOiJFUzI1NiJ9.payload.sig', emptyDef);
        expect(r.ok).toBe(true);
    });

    it('rejects empty-path field in non-optional descriptor', () => {
        const badDef: PresentationDefinition = {
            id: 'bad-pd',
            input_descriptors: [{
                id: 'bad-desc',
                constraints: {
                    fields: [{ path: [], optional: false }],
                },
            }],
        };
        const r = satisfiesConstraints('eyJhbGciOiJFUzI1NiJ9.payload.sig', badDef);
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('EMPTY_PATH');
    });
});

describe('verifyAuthorizationResponse — nonce replay protection', () => {
    it('accepts first use of a nonce', () => {
        const result = verifyAuthorizationResponse({
            response: buildResponse({ state: 'st-nonce' }),
            expectedNonce: `unique-nonce-${Date.now()}-A`,
            expectedState: 'st-nonce',
            definition: DEFINITION,
        });
        expect(result.valid).toBe(true);
    });

    it('rejects second use of same nonce (replay)', () => {
        const nonce = `replay-nonce-${Date.now()}`;
        const opts = {
            response: buildResponse({ state: 'st-r' }),
            expectedNonce: nonce,
            expectedState: 'st-r',
            definition: DEFINITION,
        };

        const first = verifyAuthorizationResponse(opts);
        expect(first.valid).toBe(true);

        const second = verifyAuthorizationResponse(opts);
        expect(second.valid).toBe(false);
        expect(second.errors.some(e => e.includes('replay') || e.includes('Nonce'))).toBe(true);
    });

    it('different nonces both accepted independently', () => {
        const r1 = verifyAuthorizationResponse({
            response: buildResponse({ state: 's1' }),
            expectedNonce: `nonce-x-${Date.now()}-1`,
            expectedState: 's1',
            definition: DEFINITION,
        });
        const r2 = verifyAuthorizationResponse({
            response: buildResponse({ state: 's2' }),
            expectedNonce: `nonce-x-${Date.now()}-2`,
            expectedState: 's2',
            definition: DEFINITION,
        });
        expect(r1.valid).toBe(true);
        expect(r2.valid).toBe(true);
    });

    it('rejects response with no descriptor map entries', () => {
        const result = verifyAuthorizationResponse({
            response: buildResponse({
                presentation_submission: {
                    id: 'sub-nodesc',
                    definition_id: 'age-pd',
                    descriptor_map: [], // empty — no mappings
                },
            }),
            expectedNonce: `nonce-nodesc-${Date.now()}`,
            definition: DEFINITION,
            skipNonceCheck: true,
        });
        // descriptor_map is empty but definition has 1 descriptor → mismatch
        expect(result.valid).toBe(false);
    });

    it('rejects when credential count < descriptor count', () => {
        const multiDef: PresentationDefinition = {
            id: 'multi-pd',
            input_descriptors: [
                { id: 'd1', constraints: { fields: [{ path: ['$.a'] }] } },
                { id: 'd2', constraints: { fields: [{ path: ['$.b'] }] } },
            ],
        };
        // Only 1 credential in vp_token but 2 descriptors required
        const result = verifyAuthorizationResponse({
            response: {
                vp_token: 'eyJhbGciOiJFUzI1NiJ9.single.credential',
                presentation_submission: {
                    id: 'sub-multi',
                    definition_id: 'multi-pd',
                    descriptor_map: [
                        { id: 'd1', format: 'sd-jwt', path: '$' },
                        { id: 'd2', format: 'sd-jwt', path: '$[1]' },
                    ],
                },
                state: 'st-multi',
            },
            expectedNonce: `nonce-multi-${Date.now()}`,
            expectedState: 'st-multi',
            definition: multiDef,
            skipNonceCheck: true,
        });
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('count') || e.includes('mismatch'))).toBe(true);
    });

    it('skipNonceCheck bypasses replay detection', () => {
        const nonce = `skip-nonce-${Date.now()}`;
        const opts = {
            response: buildResponse({ state: 'st-skip' }),
            expectedNonce: nonce,
            expectedState: 'st-skip',
            definition: DEFINITION,
            skipNonceCheck: true as const,
        };
        // Second call still passes because nonce check is skipped
        verifyAuthorizationResponse(opts);
        const second = verifyAuthorizationResponse(opts);
        expect(second.valid).toBe(true);
    });
});
