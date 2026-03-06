/**
 * OID4VP Policy Bridge Tests
 * Block E — Policy Engine Integration (Spec 111)
 */

import { describe, it, expect, vi } from 'vitest';
import {
    executeOID4VPFlow,
    mapRequestToPolicyInput,
    validateRequestCompatibility,
    type PolicyEvaluatorFn,
    type OID4VPFlowOptions,
} from '../policy-bridge';
import type { AuthorizationRequest } from '../types';

// ─── Test Fixtures ──────────────────────────────────────────────────────────

const MOCK_REQUEST = {
    response_type: 'vp_token',
    client_id: 'https://verifier.example.com',
    redirect_uri: 'https://verifier.example.com/callback',
    nonce: 'test-nonce-abc',
    presentation_definition: {
        id: 'pd-age-check',
        purpose: 'Age verification for alcohol purchase',
        input_descriptors: [
            {
                id: 'age-descriptor',
                constraints: {
                    fields: [
                        { path: ['$.credentialSubject.age'], filter: { type: 'number', minimum: 18 } },
                    ],
                },
            },
        ],
    },
};

const makeEvaluator = (verdict: 'ALLOW' | 'DENY' | 'PROMPT'): PolicyEvaluatorFn =>
    vi.fn().mockResolvedValue({
        verdict,
        reasons: verdict === 'ALLOW' ? ['RULE_MATCH'] : ['POLICY_DENY'],
        decisionId: `decision-${verdict.toLowerCase()}-001`,
    });

const makeOpts = (
    verdict: 'ALLOW' | 'DENY' | 'PROMPT',
    overrides: Partial<OID4VPFlowOptions> = {}
): OID4VPFlowOptions => ({
    evaluator: makeEvaluator(verdict),
    onPrompt: vi.fn().mockResolvedValue(true),
    holderDid: 'did:peer:0ztest',
    selectCredentials: vi.fn().mockResolvedValue(['credential-jwt-abc123']),
    ...overrides,
});

// ─── E-04: Policy Bridge Tests ───────────────────────────────────────────────

describe('E-04 — OID4VP Policy Bridge: executeOID4VPFlow', () => {
    it('ALLOW verdict: returns response with VP token', async () => {
        const result = await executeOID4VPFlow(MOCK_REQUEST, makeOpts('ALLOW'));
        expect(result.verdict).toBe('ALLOW');
        expect(result.response).toBeDefined();
        expect(result.decisionId).toBe('decision-allow-001');
        expect(result.error).toBeUndefined();
    });

    it('DENY verdict: returns DENY immediately, no response built', async () => {
        const opts = makeOpts('DENY');
        const result = await executeOID4VPFlow(MOCK_REQUEST, opts);
        expect(result.verdict).toBe('DENY');
        expect(result.response).toBeUndefined();
        expect(result.error).toMatch(/Policy denied/);
        expect(result.decisionId).toBe('decision-deny-001');
        // onPrompt must NOT be called on DENY
        expect(opts.onPrompt).not.toHaveBeenCalled();
        // selectCredentials must NOT be called on DENY
        expect(opts.selectCredentials).not.toHaveBeenCalled();
    });

    it('PROMPT verdict + user grants: flow continues to ALLOW', async () => {
        const opts = makeOpts('PROMPT', {
            onPrompt: vi.fn().mockResolvedValue(true),
        });
        const result = await executeOID4VPFlow(MOCK_REQUEST, opts);
        expect(result.verdict).toBe('ALLOW');
        expect(opts.onPrompt).toHaveBeenCalledOnce();
        expect(result.response).toBeDefined();
    });

    it('PROMPT verdict + user denies: returns DENY with USER_DENIED', async () => {
        const opts = makeOpts('PROMPT', {
            onPrompt: vi.fn().mockResolvedValue(false),
        });
        const result = await executeOID4VPFlow(MOCK_REQUEST, opts);
        expect(result.verdict).toBe('DENY');
        expect(result.error).toBe('User denied consent');
        expect(result.reasons).toContain('USER_DENIED');
        expect(opts.selectCredentials).not.toHaveBeenCalled();
    });

    it('invalid request: parse failure returns DENY', async () => {
        const opts = makeOpts('ALLOW');
        const result = await executeOID4VPFlow({ not_a_valid_request: true }, opts);
        expect(result.verdict).toBe('DENY');
        expect(result.error).toBeDefined();
        // Evaluator must NOT be called if parsing fails
        expect(opts.evaluator).not.toHaveBeenCalled();
    });

    it('no matching credentials: returns DENY with NO_MATCHING_CREDENTIALS', async () => {
        const opts = makeOpts('ALLOW', {
            selectCredentials: vi.fn().mockResolvedValue([]),
        });
        const result = await executeOID4VPFlow(MOCK_REQUEST, opts);
        expect(result.verdict).toBe('DENY');
        expect(result.reasons).toContain('NO_MATCHING_CREDENTIALS');
    });

    it('evaluator receives correct policy input from request', async () => {
        const evaluatorSpy = makeEvaluator('ALLOW');
        const opts = makeOpts('ALLOW', { evaluator: evaluatorSpy });
        await executeOID4VPFlow(MOCK_REQUEST, opts);

        expect(evaluatorSpy).toHaveBeenCalledWith(
            expect.objectContaining({
                verifierId: MOCK_REQUEST.client_id,
                nonce: MOCK_REQUEST.nonce,
                definition: expect.objectContaining({ id: 'pd-age-check' }),
            })
        );
    });

    it('consent context passed to onPrompt has correct shape', async () => {
        const onPromptSpy = vi.fn().mockResolvedValue(true);
        const opts = makeOpts('PROMPT', { onPrompt: onPromptSpy });
        await executeOID4VPFlow(MOCK_REQUEST, opts);

        expect(onPromptSpy).toHaveBeenCalledWith(
            expect.objectContaining({
                verifierName: undefined, // no client_metadata in fixture
                purpose: 'Age verification for alcohol purchase',
                requestedPaths: expect.arrayContaining(['$.credentialSubject.age']),
                requiresSD: false,
            })
        );
    });

    it('response contains nonce from original request', async () => {
        const result = await executeOID4VPFlow(MOCK_REQUEST, makeOpts('ALLOW'));
        expect(result.response?.presentation_submission).toBeDefined();
    });

    it('verifierName is populated from client_metadata', async () => {
        const requestWithMeta = {
            ...MOCK_REQUEST,
            client_metadata: { client_name: 'Liquor Store GmbH' },
        };
        const onPromptSpy = vi.fn().mockResolvedValue(true);
        const opts = makeOpts('PROMPT', { onPrompt: onPromptSpy });
        await executeOID4VPFlow(requestWithMeta, opts);

        expect(onPromptSpy).toHaveBeenCalledWith(
            expect.objectContaining({ verifierName: 'Liquor Store GmbH' })
        );
    });
});

// ─── E-04: mapRequestToPolicyInput ──────────────────────────────────────────

describe('E-04 — mapRequestToPolicyInput', () => {
    const req: AuthorizationRequest = {
        response_type: 'vp_token',
        client_id: 'https://shop.at',
        redirect_uri: 'https://shop.at/callback',
        nonce: 'nonce-xyz',
        presentation_definition: {
            id: 'pd-shop',
            input_descriptors: [{ id: 'desc-1', constraints: { fields: [] } }],
        },
    };

    it('maps client_id → verifierId', () => {
        const input = mapRequestToPolicyInput(req);
        expect(input.verifierId).toBe('https://shop.at');
    });

    it('maps nonce correctly', () => {
        const input = mapRequestToPolicyInput(req);
        expect(input.nonce).toBe('nonce-xyz');
    });

    it('maps presentation_definition correctly', () => {
        const input = mapRequestToPolicyInput(req);
        expect(input.definition.id).toBe('pd-shop');
    });

    it('holderDid is undefined when not provided', () => {
        const input = mapRequestToPolicyInput(req);
        expect(input.holderDid).toBeUndefined();
    });
});

// ─── E-04: validateRequestCompatibility ─────────────────────────────────────

describe('E-04 — validateRequestCompatibility', () => {
    const makeReq = (paths: string[]): AuthorizationRequest => ({
        response_type: 'vp_token',
        client_id: 'https://allowed-verifier.example',
        redirect_uri: 'https://allowed-verifier.example/callback',
        nonce: 'nonce-compat',
        presentation_definition: {
            id: 'pd-compat',
            input_descriptors: [
                {
                    id: 'desc-compat',
                    constraints: {
                        fields: paths.map(p => ({ path: [p] })),
                    },
                },
            ],
        },
    });

    it('passes with ≤ 10 claim paths and allowed verifier', () => {
        const req = makeReq(['$.name', '$.age', '$.dob']);
        const result = validateRequestCompatibility(req, ['https://allowed-verifier.example']);
        expect(result.ok).toBe(true);
    });

    it('fails with > 10 claim paths (TOO_MANY_CLAIMS)', () => {
        const paths = Array.from({ length: 11 }, (_, i) => `$.field${i}`);
        const req = makeReq(paths);
        const result = validateRequestCompatibility(req, []);
        expect(result.ok).toBe(false);
        expect(result.code).toBe('TOO_MANY_CLAIMS');
        expect(result.error).toMatch(/11 claim paths/);
    });

    it('fails with verifier not in allowlist (VERIFIER_NOT_ALLOWED)', () => {
        const req = makeReq(['$.age']);
        const result = validateRequestCompatibility(req, ['https://other.example']);
        expect(result.ok).toBe(false);
        expect(result.code).toBe('VERIFIER_NOT_ALLOWED');
    });

    it('empty allowlist passes any verifier', () => {
        const req = makeReq(['$.age']);
        const result = validateRequestCompatibility(req, []);
        expect(result.ok).toBe(true);
    });

    it('custom maxClaimsPerRequest respected', () => {
        const paths = Array.from({ length: 3 }, (_, i) => `$.field${i}`);
        const req = makeReq(paths);
        const result = validateRequestCompatibility(req, [], 2);
        expect(result.ok).toBe(false);
        expect(result.code).toBe('TOO_MANY_CLAIMS');
    });
});
