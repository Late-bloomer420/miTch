import { describe, it, expect } from 'vitest';
import {
    parseAuthorizationRequest,
    parsePresentationDefinition,
    extractRequestedPaths,
    requiresSelectiveDisclosure,
} from '../presentation-request';
import { buildVPToken, buildVerifiablePresentation, parseVPToken, validateSubmission } from '../vp-token';
import { buildAuthorizationResponse, encodeDirectPost, decodeDirectPost } from '../response-builder';
import type { PresentationDefinition, AuthorizationRequest } from '../types';

// ─── Fixtures ─────────────────────────────────────────────────────

const DEFINITION: PresentationDefinition = {
    id: 'age-check-pd',
    name: 'Age Verification',
    purpose: 'Verify user is over 18',
    input_descriptors: [
        {
            id: 'age-descriptor',
            constraints: {
                limit_disclosure: 'required',
                fields: [{ path: ['$.credentialSubject.age'] }],
            },
        },
    ],
};

const REQUEST: AuthorizationRequest = {
    response_type: 'vp_token',
    client_id: 'https://shop.example.at',
    redirect_uri: 'https://shop.example.at/callback',
    nonce: 'nonce-xyz-123',
    presentation_definition: DEFINITION,
    state: 'state-abc',
    response_mode: 'direct_post',
};

// ─── Presentation Request Tests ────────────────────────────────────

describe('parseAuthorizationRequest', () => {
    it('parses valid request', () => {
        const result = parseAuthorizationRequest(REQUEST);
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.value!.client_id).toBe('https://shop.example.at');
            expect(result.value!.nonce).toBe('nonce-xyz-123');
        }
    });

    it('rejects invalid response_type', () => {
        const r = parseAuthorizationRequest({ ...REQUEST, response_type: 'code' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('INVALID_RESPONSE_TYPE');
    });

    it('rejects missing client_id', () => {
        const { client_id, ...rest } = REQUEST;
        const r = parseAuthorizationRequest(rest);
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('MISSING_CLIENT_ID');
    });

    it('rejects missing nonce', () => {
        const r = parseAuthorizationRequest({ ...REQUEST, nonce: '' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('MISSING_NONCE');
    });

    it('rejects null input', () => {
        const r = parseAuthorizationRequest(null);
        expect(r.ok).toBe(false);
    });
});

describe('parsePresentationDefinition', () => {
    it('parses valid definition', () => {
        const r = parsePresentationDefinition(DEFINITION);
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.value!.input_descriptors).toHaveLength(1);
    });

    it('rejects missing id', () => {
        const r = parsePresentationDefinition({ input_descriptors: [{ id: 'x' }] });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('MISSING_PD_ID');
    });

    it('rejects empty input_descriptors', () => {
        const r = parsePresentationDefinition({ id: 'pd1', input_descriptors: [] });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('MISSING_INPUT_DESCRIPTORS');
    });
});

describe('extractRequestedPaths', () => {
    it('extracts paths from constraints', () => {
        const paths = extractRequestedPaths(DEFINITION);
        expect(paths).toContain('$.credentialSubject.age');
    });

    it('returns empty for definition without field constraints', () => {
        const pd: PresentationDefinition = {
            id: 'pd2',
            input_descriptors: [{ id: 'd1' }],
        };
        expect(extractRequestedPaths(pd)).toHaveLength(0);
    });
});

describe('requiresSelectiveDisclosure', () => {
    it('returns true when limit_disclosure = required', () => {
        expect(requiresSelectiveDisclosure(DEFINITION)).toBe(true);
    });

    it('returns false without limit_disclosure', () => {
        const pd: PresentationDefinition = {
            id: 'pd3',
            input_descriptors: [{ id: 'd2' }],
        };
        expect(requiresSelectiveDisclosure(pd)).toBe(false);
    });
});

// ─── VP Token Tests ────────────────────────────────────────────────

describe('buildVPToken', () => {
    it('builds single-credential token', () => {
        const token = buildVPToken({
            holder: 'did:example:holder',
            credentials: ['eyJhbGc...'],
            definition: DEFINITION,
        });
        expect(token.vp_token).toBe('eyJhbGc...');
        expect(token.presentation_submission.definition_id).toBe('age-check-pd');
        expect(token.presentation_submission.descriptor_map[0].path).toBe('$');
    });

    it('uses array path for multi-credential', () => {
        const multi: PresentationDefinition = {
            id: 'multi-pd',
            input_descriptors: [{ id: 'd1' }, { id: 'd2' }],
        };
        const token = buildVPToken({
            holder: 'did:example:holder',
            credentials: ['cred1', 'cred2'],
            definition: multi,
        });
        expect(token.presentation_submission.descriptor_map[0].path).toBe('$[0]');
        expect(token.presentation_submission.descriptor_map[1].path).toBe('$[1]');
    });

    it('generates unique submission IDs', () => {
        const t1 = buildVPToken({ holder: 'h', credentials: ['c1'], definition: DEFINITION });
        const t2 = buildVPToken({ holder: 'h', credentials: ['c1'], definition: DEFINITION });
        expect(t1.presentation_submission.id).not.toBe(t2.presentation_submission.id);
    });
});

describe('validateSubmission', () => {
    it('validates matching submission', () => {
        const token = buildVPToken({ holder: 'h', credentials: ['c'], definition: DEFINITION });
        const result = validateSubmission(token.presentation_submission, DEFINITION);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    it('detects definition_id mismatch', () => {
        const token = buildVPToken({ holder: 'h', credentials: ['c'], definition: DEFINITION });
        const wrong = { ...DEFINITION, id: 'different-pd' };
        const result = validateSubmission(token.presentation_submission, wrong);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('mismatch'))).toBe(true);
    });
});

// ─── Response Builder Tests ────────────────────────────────────────

describe('buildAuthorizationResponse', () => {
    it('builds response on granted consent', () => {
        const r = buildAuthorizationResponse({
            request: REQUEST,
            holder: 'did:example:alice',
            consent: { granted: true, selectedCredentials: ['cred~abc'] },
        });
        expect(r.ok).toBe(true);
        if (r.ok) {
            expect(r.value!.state).toBe('state-abc');
            expect(r.value!.vp_token).toBeTruthy();
        }
    });

    it('returns error on denied consent', () => {
        const r = buildAuthorizationResponse({
            request: REQUEST,
            holder: 'did:example:alice',
            consent: { granted: false, reason: 'User declined' },
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('USER_DENIED');
    });

    it('returns error when no credentials selected', () => {
        const r = buildAuthorizationResponse({
            request: REQUEST,
            holder: 'did:example:alice',
            consent: { granted: true, selectedCredentials: [] },
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('NO_CREDENTIALS');
    });
});

describe('encodeDirectPost / decodeDirectPost', () => {
    it('round-trips a response', () => {
        const response = {
            vp_token: 'eyJhbGc...',
            presentation_submission: {
                id: 'sub-1',
                definition_id: 'age-check-pd',
                descriptor_map: [{ id: 'age-descriptor', format: 'sd-jwt' as const, path: '$' }],
            },
            state: 'state-abc',
        };
        const encoded = encodeDirectPost(response);
        const decoded = decodeDirectPost(encoded);
        expect(decoded.ok).toBe(true);
        if (decoded.ok) {
            expect(decoded.value!.vp_token).toBe('eyJhbGc...');
            expect(decoded.value!.state).toBe('state-abc');
        }
    });

    it('returns error on missing vp_token', () => {
        const r = decodeDirectPost('presentation_submission=%7B%7D');
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('MISSING_VP_TOKEN');
    });
});
