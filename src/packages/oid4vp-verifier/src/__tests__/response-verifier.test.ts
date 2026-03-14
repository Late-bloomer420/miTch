import { describe, it, expect } from 'vitest';
import {
    verifyAuthorizationResponse,
    satisfiesConstraints,
} from '../response-verifier';
import type {
    PresentationDefinition,
    AuthorizationResponse,
    PresentationSubmission,
    VerifiablePresentation,
} from '@mitch/oid4vp';

// ─── Fixtures ─────────────────────────────────────────────────────

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

const MULTI_DESCRIPTOR_DEF: PresentationDefinition = {
    id: 'multi-pd',
    input_descriptors: [
        {
            id: 'name-descriptor',
            constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
        },
        {
            id: 'address-descriptor',
            constraints: { fields: [{ path: ['$.credentialSubject.address'] }] },
        },
    ],
};

const VALID_VP_TOKEN = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig';

function buildSubmission(overrides: Partial<PresentationSubmission> = {}): PresentationSubmission {
    return {
        id: 'sub-1',
        definition_id: 'age-pd',
        descriptor_map: [{ id: 'age-descriptor', format: 'sd-jwt', path: '$' }],
        ...overrides,
    };
}

function buildResponse(overrides: Partial<AuthorizationResponse> = {}): AuthorizationResponse {
    return {
        vp_token: VALID_VP_TOKEN,
        presentation_submission: buildSubmission(),
        state: 'state-abc',
        ...overrides,
    };
}

let nonceCounter = 0;
function uniqueNonce(): string {
    return `nonce-rv-test-${Date.now()}-${++nonceCounter}`;
}

// ─── verifyAuthorizationResponse ──────────────────────────────────

describe('verifyAuthorizationResponse', () => {
    describe('valid responses', () => {
        it('accepts a well-formed response (skipNonceCheck)', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse(),
                expectedNonce: uniqueNonce(),
                expectedState: 'state-abc',
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
            expect(result.credentials).toHaveLength(1);
            expect(result.credentials[0]).toBe(VALID_VP_TOKEN);
        });

        it('accepts response without expectedState check', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({ state: 'anything' }),
                expectedNonce: uniqueNonce(),
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(true);
        });

        it('passes nonce check with fresh nonce', () => {
            const nonce = uniqueNonce();
            const result = verifyAuthorizationResponse({
                response: buildResponse(),
                expectedNonce: nonce,
                expectedState: 'state-abc',
                definition: DEFINITION,
                // Note: NOT skipping nonce check
            });
            expect(result.valid).toBe(true);
        });
    });

    describe('nonce replay detection', () => {
        it('rejects replayed nonce', () => {
            const nonce = uniqueNonce();

            // First use should pass
            const r1 = verifyAuthorizationResponse({
                response: buildResponse(),
                expectedNonce: nonce,
                expectedState: 'state-abc',
                definition: DEFINITION,
            });
            expect(r1.valid).toBe(true);

            // Second use should detect replay
            const r2 = verifyAuthorizationResponse({
                response: buildResponse(),
                expectedNonce: nonce,
                expectedState: 'state-abc',
                definition: DEFINITION,
            });
            expect(r2.valid).toBe(false);
            expect(r2.errors).toContain('Nonce replay detected');
        });

        it('allows different nonces', () => {
            const r1 = verifyAuthorizationResponse({
                response: buildResponse(),
                expectedNonce: uniqueNonce(),
                expectedState: 'state-abc',
                definition: DEFINITION,
            });
            const r2 = verifyAuthorizationResponse({
                response: buildResponse(),
                expectedNonce: uniqueNonce(),
                expectedState: 'state-abc',
                definition: DEFINITION,
            });
            expect(r1.valid).toBe(true);
            expect(r2.valid).toBe(true);
        });
    });

    describe('state mismatch', () => {
        it('rejects when state does not match', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({ state: 'wrong-state' }),
                expectedNonce: uniqueNonce(),
                expectedState: 'state-abc',
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('State mismatch'))).toBe(true);
        });

        it('rejects when state is undefined but expected', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({ state: undefined }),
                expectedNonce: uniqueNonce(),
                expectedState: 'state-abc',
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('State mismatch'))).toBe(true);
        });

        it('includes expected and actual values in error message', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({ state: 'actual-state' }),
                expectedNonce: uniqueNonce(),
                expectedState: 'expected-state',
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.errors[0]).toContain('expected-state');
            expect(result.errors[0]).toContain('actual-state');
        });
    });

    describe('submission validation', () => {
        it('rejects when definition_id does not match', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({
                    presentation_submission: buildSubmission({ definition_id: 'wrong-id' }),
                }),
                expectedNonce: uniqueNonce(),
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('mismatch'))).toBe(true);
        });

        it('rejects when required descriptor is missing from map', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({
                    presentation_submission: buildSubmission({
                        descriptor_map: [], // missing required age-descriptor
                    }),
                }),
                expectedNonce: uniqueNonce(),
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('Missing descriptor'))).toBe(true);
        });
    });

    describe('VP token validation', () => {
        it('rejects empty vp_token string', () => {
            const result = verifyAuthorizationResponse({
                response: buildResponse({ vp_token: '' }),
                expectedNonce: uniqueNonce(),
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('no credentials'))).toBe(true);
        });

        it('accepts W3C VP object with verifiableCredential', () => {
            const vpObject = {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [VALID_VP_TOKEN],
                holder: 'did:example:holder',
            };
            const result = verifyAuthorizationResponse({
                response: buildResponse({ vp_token: vpObject as VerifiablePresentation }),
                expectedNonce: uniqueNonce(),
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(true);
            expect(result.credentials).toContain(VALID_VP_TOKEN);
        });

        it('rejects W3C VP object with empty verifiableCredential', () => {
            const vpObject = {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiablePresentation'],
                verifiableCredential: [],
                holder: 'did:example:holder',
            };
            const result = verifyAuthorizationResponse({
                response: buildResponse({ vp_token: vpObject as VerifiablePresentation }),
                expectedNonce: uniqueNonce(),
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
        });
    });

    describe('credential count vs descriptor count', () => {
        it('rejects when fewer credentials than descriptors', () => {
            // Multi-descriptor definition requires 2 credentials, but we only supply 1
            const result = verifyAuthorizationResponse({
                response: {
                    vp_token: VALID_VP_TOKEN, // single credential string
                    presentation_submission: {
                        id: 'sub-multi',
                        definition_id: 'multi-pd',
                        descriptor_map: [
                            { id: 'name-descriptor', format: 'sd-jwt', path: '$[0]' },
                            { id: 'address-descriptor', format: 'sd-jwt', path: '$[1]' },
                        ],
                    },
                    state: 's',
                },
                expectedNonce: uniqueNonce(),
                definition: MULTI_DESCRIPTOR_DEF,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('Credential count mismatch'))).toBe(true);
        });
    });

    describe('multiple simultaneous errors', () => {
        it('collects all errors (state + submission + empty token)', () => {
            const result = verifyAuthorizationResponse({
                response: {
                    vp_token: '',
                    presentation_submission: buildSubmission({ definition_id: 'wrong' }),
                    state: 'bad',
                },
                expectedNonce: uniqueNonce(),
                expectedState: 'good',
                definition: DEFINITION,
                skipNonceCheck: true,
            });
            expect(result.valid).toBe(false);
            // Should have at least 3 errors: state, definition_id, empty token
            expect(result.errors.length).toBeGreaterThanOrEqual(3);
        });
    });
});

// ─── satisfiesConstraints ─────────────────────────────────────────

describe('satisfiesConstraints', () => {
    it('accepts valid credential with sufficient length', () => {
        const result = satisfiesConstraints('eyJhbGciOiJFUzI1NiJ9.payload.sig', DEFINITION);
        expect(result.ok).toBe(true);
    });

    it('rejects empty credential', () => {
        const result = satisfiesConstraints('', DEFINITION);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('INVALID_CREDENTIAL');
            expect(result.error).toContain('too short');
        }
    });

    it('rejects credential shorter than 10 chars', () => {
        const result = satisfiesConstraints('short', DEFINITION);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.code).toBe('INVALID_CREDENTIAL');
    });

    it('accepts credential of exactly 10 chars', () => {
        const result = satisfiesConstraints('1234567890', DEFINITION);
        expect(result.ok).toBe(true);
    });

    it('rejects definition with empty field path', () => {
        const defWithEmptyPath: PresentationDefinition = {
            id: 'empty-path-pd',
            input_descriptors: [
                {
                    id: 'desc-1',
                    constraints: {
                        fields: [{ path: [] }], // empty path, not optional
                    },
                },
            ],
        };
        const result = satisfiesConstraints('valid-credential-string', defWithEmptyPath);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('EMPTY_PATH');
            expect(result.error).toContain('desc-1');
        }
    });

    it('accepts optional field with empty path', () => {
        const defWithOptionalEmptyPath: PresentationDefinition = {
            id: 'opt-pd',
            input_descriptors: [
                {
                    id: 'desc-opt',
                    constraints: {
                        fields: [{ path: [], optional: true }],
                    },
                },
            ],
        };
        // optional fields with empty paths should not trigger EMPTY_PATH error
        const result = satisfiesConstraints('valid-credential-string', defWithOptionalEmptyPath);
        expect(result.ok).toBe(true);
    });

    it('accepts definition with no constraints', () => {
        const defNoConstraints: PresentationDefinition = {
            id: 'nc-pd',
            input_descriptors: [{ id: 'desc-nc' }],
        };
        const result = satisfiesConstraints('valid-credential-string', defNoConstraints);
        expect(result.ok).toBe(true);
    });

    it('accepts definition with constraints but no fields', () => {
        const defNoFields: PresentationDefinition = {
            id: 'nf-pd',
            input_descriptors: [
                { id: 'desc-nf', constraints: { limit_disclosure: 'required' } },
            ],
        };
        const result = satisfiesConstraints('valid-credential-string', defNoFields);
        expect(result.ok).toBe(true);
    });

    it('checks all descriptors (fails on second descriptor)', () => {
        const def: PresentationDefinition = {
            id: 'two-desc-pd',
            input_descriptors: [
                {
                    id: 'desc-ok',
                    constraints: { fields: [{ path: ['$.name'] }] },
                },
                {
                    id: 'desc-bad',
                    constraints: { fields: [{ path: [] }] }, // empty, non-optional
                },
            ],
        };
        const result = satisfiesConstraints('valid-credential-string', def);
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.code).toBe('EMPTY_PATH');
            expect(result.error).toContain('desc-bad');
        }
    });
});
