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
});
