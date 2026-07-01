import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import { ProtectionLayer } from '@askmi/layer-resolver';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@askmi/shared-types';

const makeCredential = (overrides: Partial<StoredCredentialMetadata> = {}): StoredCredentialMetadata => ({
    id: 'cred-001',
    type: ['IDCredential'],
    issuer: 'did:example:gov',
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    claims: ['age', 'dob', 'address'],
    ...overrides,
});

const makeRequest = (overrides: Partial<VerifierRequest> = {}): VerifierRequest => ({
    verifierId: 'did:web:example.com',
    requestedClaims: ['age'],
    requirements: [
        { credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: [] },
    ],
    nonce: 'nonce-001',
    ...overrides,
});

const makePolicy = (overrides: Partial<PolicyManifest> = {}): PolicyManifest => ({
    version: '1.0.0',
    trustedIssuers: [
        { did: 'did:example:gov', name: 'Gov', credentialTypes: ['IDCredential'] },
    ],
    rules: [
        {
            id: 'test-rule',
            verifierPattern: 'did:web:example.com',
            minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
            allowedClaims: ['age'],
            provenClaims: [],
            requiresTrustedIssuer: true,
            maxCredentialAgeDays: 365,
            requiresUserConsent: false,
            priority: 10,
        },
    ],
    globalSettings: { blockUnknownVerifiers: true },
    ...overrides,
});

const ctx = (overrides: Partial<EvaluationContext> = {}): EvaluationContext => ({
    timestamp: Date.now(),
    userDID: 'did:example:alice',
    ...overrides,
});

describe('engine.ts — internal rate-limiter', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('DENY RATE_LIMIT_EXCEEDED after 11 requests from same verifier', async () => {
        const policy = makePolicy();
        const request = makeRequest();
        const cred = makeCredential();

        for (let i = 0; i < 10; i++) {
            await engine.evaluate(request, ctx(), [cred], policy);
        }

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain('RATE_LIMIT_EXCEEDED');
    });

    it('does not trigger rate limit below threshold', async () => {
        const policy = makePolicy();
        const request = makeRequest();
        const cred = makeCredential();

        for (let i = 0; i < 9; i++) {
            const r = await engine.evaluate(request, ctx(), [cred], policy);
            expect(r.reasonCodes).not.toContain('RATE_LIMIT_EXCEEDED');
        }
    });
});

describe('engine.ts — HIGH_RISK_VERIFIER escalation', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('PROMPT HIGH_RISK_VERIFIER when excess claims accumulate risk above threshold', async () => {
        // allowedClaims has 1 entry; request has 4 claims → excess = 3 per call
        // After 2 calls: riskScore = 6 > RISK_THRESHOLD(5)
        const policy = makePolicy({
            rules: [{
                id: 'test-rule',
                verifierPattern: 'did:web:example.com',
                minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                allowedClaims: ['age'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                maxCredentialAgeDays: 365,
                requiresUserConsent: false,
                priority: 10,
            }],
        });

        const request = makeRequest({
            requirements: [{
                credentialType: 'IDCredential',
                requestedClaims: ['age', 'dob', 'address', 'phone'],
                requestedProvenClaims: [],
            }],
        });
        const cred = makeCredential();

        await engine.evaluate(request, ctx(), [cred], policy); // risk = 3
        await engine.evaluate(request, ctx(), [cred], policy); // risk = 6

        const result = await engine.evaluate(request, ctx(), [cred], policy); // risk > 5
        expect(result.verdict).toBe('PROMPT');
        expect(result.reasonCodes).toContain('HIGH_RISK_VERIFIER');
    });

    it('does not escalate when rule requiresUserConsent is already true', async () => {
        const policy = makePolicy({
            rules: [{
                id: 'consent-rule',
                verifierPattern: 'did:web:example.com',
                minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                allowedClaims: ['age'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                maxCredentialAgeDays: 365,
                requiresUserConsent: true,
                priority: 10,
            }],
        });

        const request = makeRequest({
            requirements: [{
                credentialType: 'IDCredential',
                requestedClaims: ['age', 'dob', 'address', 'phone'],
                requestedProvenClaims: [],
            }],
        });
        const cred = makeCredential();

        // Drive risk above threshold
        await engine.evaluate(request, ctx(), [cred], policy);
        await engine.evaluate(request, ctx(), [cred], policy);

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.reasonCodes).not.toContain('HIGH_RISK_VERIFIER');
    });
});

describe('engine.ts — overrideGranted synthetic rule', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('does not return UNKNOWN_VERIFIER when context.overrideGranted is true', async () => {
        const policy = makePolicy({ globalSettings: { blockUnknownVerifiers: true } });
        const request = makeRequest({ verifierId: 'did:unknown:unregistered-verifier' });
        const cred = makeCredential();

        const result = await engine.evaluate(request, ctx({ overrideGranted: true }), [cred], policy);
        // Override bypasses the UNKNOWN_VERIFIER block; even if DENY for other reasons (e.g.
        // empty allowedClaims in the synthetic rule), UNKNOWN_VERIFIER must not be the reason.
        expect(result.reasonCodes).not.toContain(ReasonCode.UNKNOWN_VERIFIER);
    });

    it('DENY UNKNOWN_VERIFIER without override for unknown verifier', async () => {
        const policy = makePolicy({ globalSettings: { blockUnknownVerifiers: true } });
        const request = makeRequest({ verifierId: 'did:unknown:unregistered-verifier' });
        const cred = makeCredential();

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.UNKNOWN_VERIFIER);
    });
});

describe('engine.ts — blockUnknownVerifiers: false', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('returns NO_MATCHING_RULE (not UNKNOWN_VERIFIER) when blockUnknownVerifiers is false', async () => {
        const policy = makePolicy({ globalSettings: { blockUnknownVerifiers: false } });
        const request = makeRequest({ verifierId: 'did:unknown:no-rule-verifier' });
        const cred = makeCredential();

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.NO_MATCHING_RULE);
        expect(result.reasonCodes).not.toContain(ReasonCode.UNKNOWN_VERIFIER);
    });
});

describe('engine.ts — S-11 vulnerable claims require Layer 2 authorization', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('DENY LAYER_VIOLATION when a WELT/default verifier requests bloodGroup', async () => {
        const policy = makePolicy({
            trustedIssuers: [
                { did: 'did:example:ehealth', name: 'eHealth', credentialTypes: ['PatientSummary'] },
            ],
            rules: [{
                id: 'welt-health-rule',
                verifierPattern: 'did:web:example.com',
                allowedClaims: ['bloodGroup'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                requiresUserConsent: false,
                priority: 10,
            }],
        });
        const request = makeRequest({
            requirements: [{
                credentialType: 'PatientSummary',
                requestedClaims: ['bloodGroup'],
                requestedProvenClaims: [],
            }],
        });
        const cred = makeCredential({
            type: ['PatientSummary'],
            issuer: 'did:example:ehealth',
            claims: ['bloodGroup'],
        });

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.LAYER_VIOLATION);
    });

    it('DENY LAYER_VIOLATION when a Layer-1 verifier requests licenseId', async () => {
        const policy = makePolicy({
            trustedIssuers: [
                { did: 'did:example:hospital', name: 'Hospital', credentialTypes: ['EmploymentCredential'] },
            ],
            rules: [{
                id: 'layer1-professional-rule',
                verifierPattern: 'did:web:example.com',
                minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                allowedClaims: ['licenseId'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                requiresUserConsent: false,
                priority: 10,
            }],
        });
        const request = makeRequest({
            requirements: [{
                credentialType: 'EmploymentCredential',
                requestedClaims: ['licenseId'],
                requestedProvenClaims: [],
            }],
        });
        const cred = makeCredential({
            type: ['EmploymentCredential'],
            issuer: 'did:example:hospital',
            claims: ['licenseId'],
        });

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.LAYER_VIOLATION);
    });
});

describe('engine.ts — strictVerifierBinding', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('ALLOW when did:web hostname matches request origin', async () => {
        const policy = makePolicy({
            rules: [{
                id: 'web-rule',
                verifierPattern: 'did:web:example.com',
                minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                allowedClaims: ['age'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                maxCredentialAgeDays: 365,
                requiresUserConsent: false,
                priority: 10,
            }],
            globalSettings: { blockUnknownVerifiers: true, strictVerifierBinding: true },
        });
        const request = makeRequest({
            verifierId: 'did:web:example.com',
            origin: 'https://example.com',
        });

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.verdict).not.toContain('UNKNOWN_VERIFIER');
        expect(result.reasonCodes).not.toContain(ReasonCode.UNKNOWN_VERIFIER);
    });

    it('DENY when origin hostname does not match verifier DID', async () => {
        const policy = makePolicy({
            rules: [{
                id: 'web-rule',
                verifierPattern: 'did:web:example.com',
                minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                allowedClaims: ['age'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                maxCredentialAgeDays: 365,
                requiresUserConsent: false,
                priority: 10,
            }],
            globalSettings: { blockUnknownVerifiers: true, strictVerifierBinding: true },
        });
        const request = makeRequest({
            verifierId: 'did:web:example.com',
            origin: 'https://evil.com',
        });

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.UNKNOWN_VERIFIER);
    });

    it('DENY when origin is unparseable', async () => {
        const policy = makePolicy({
            rules: [{
                id: 'web-rule',
                verifierPattern: 'did:web:example.com',
                minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                allowedClaims: ['age'],
                provenClaims: [],
                requiresTrustedIssuer: true,
                maxCredentialAgeDays: 365,
                requiresUserConsent: false,
                priority: 10,
            }],
            globalSettings: { blockUnknownVerifiers: true, strictVerifierBinding: true },
        });
        const request = makeRequest({
            verifierId: 'did:web:example.com',
            origin: 'not-a-valid-url',
        });

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.UNKNOWN_VERIFIER);
    });

    it('no origin check when strictVerifierBinding is not set', async () => {
        const policy = makePolicy({
            globalSettings: { blockUnknownVerifiers: true },
        });
        const request = makeRequest({
            verifierId: 'did:web:example.com',
            origin: 'https://totally-different.com',
        });

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.reasonCodes).not.toContain(ReasonCode.UNKNOWN_VERIFIER);
    });
});

describe('engine.ts — F-02 verifier pattern matching is ReDoS-safe glob matching', () => {
    let matchesPattern: (pattern: string, value: string) => boolean;

    beforeEach(() => {
        const engine = new PolicyEngine();
        matchesPattern = (
            engine as unknown as { matchesPattern: (pattern: string, value: string) => boolean }
        ).matchesPattern.bind(engine);
    });

    it('treats regex metacharacters as literals, except the supported * glob wildcard', () => {
        expect(matchesPattern('did:web:example.com', 'did:web:exampleXcom')).toBe(false);
        expect(matchesPattern('did:web:example.com+', 'did:web:example.commmmm')).toBe(false);
        expect(matchesPattern('did:web:*.example.com', 'did:web:shop.example.com')).toBe(true);
    });

    it('rejects pathological regex-looking patterns without evaluating them as regex', () => {
        const started = performance.now();

        expect(matchesPattern('(a+)+$', `${'a'.repeat(1000)}!`)).toBe(false);

        expect(performance.now() - started).toBeLessThan(50);
    });

    it('fails closed on oversized patterns and values', () => {
        expect(matchesPattern(`${'a'.repeat(257)}*`, 'anything')).toBe(false);
        expect(matchesPattern('did:web:*', `did:web:${'a'.repeat(1025)}`)).toBe(false);
    });
});

describe('engine.ts — ERR_FUTURE_ISSUANCE sanity check', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('DENY ERR_FUTURE_ISSUANCE when credential issuedAt is in the future', async () => {
        const futureCredential = makeCredential({
            issuedAt: new Date(Date.now() + 60_000).toISOString(),
        });
        const policy = makePolicy();
        const request = makeRequest();

        const result = await engine.evaluate(request, ctx(), [futureCredential], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain('ERR_FUTURE_ISSUANCE');
    });

    it('does not flag credential with current issuedAt', async () => {
        const cred = makeCredential({ issuedAt: new Date(Date.now() - 1000).toISOString() });
        const policy = makePolicy();
        const request = makeRequest();

        const result = await engine.evaluate(request, ctx(), [cred], policy);
        expect(result.reasonCodes).not.toContain('ERR_FUTURE_ISSUANCE');
    });
});

describe('engine.ts — delegationRules AGENT_LIMIT_EXCEEDED', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('DENY AGENT_LIMIT_EXCEEDED when request exceeds max_claims_per_request', async () => {
        const policy = makePolicy({
            delegationRules: {
                allowed_agent_dids: [],
                limits: { max_claims_per_request: 2 },
                audit_level: 'NONE',
            },
        });
        const request = makeRequest({
            requirements: [{
                credentialType: 'IDCredential',
                requestedClaims: ['age', 'dob', 'address'],
                requestedProvenClaims: [],
            }],
        });

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.AGENT_LIMIT_EXCEEDED);
    });

    it('does not deny when claims are within limit', async () => {
        const policy = makePolicy({
            delegationRules: {
                allowed_agent_dids: [],
                limits: { max_claims_per_request: 5 },
                audit_level: 'NONE',
            },
        });
        const request = makeRequest();

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.reasonCodes).not.toContain(ReasonCode.AGENT_LIMIT_EXCEEDED);
    });

    it('uses legacy requestedClaims field when requirements is absent', async () => {
        const policy = makePolicy({
            delegationRules: {
                allowed_agent_dids: [],
                limits: { max_claims_per_request: 1 },
                audit_level: 'NONE',
            },
        });
        const request: VerifierRequest = {
            verifierId: 'did:web:example.com',
            requestedClaims: ['age', 'dob'],
            requirements: [],
            nonce: 'nonce-001',
        };

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.verdict).toBe('DENY');
        expect(result.reasonCodes).toContain(ReasonCode.AGENT_LIMIT_EXCEEDED);
    });
});

describe('engine.ts — ephemeralResponseKey export', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('attaches exported JWK to decisionCapsule when ephemeralResponseKey is provided', async () => {
        const ephemeralKey = await globalThis.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        const policy = makePolicy();
        const request = makeRequest({ ephemeralResponseKey: ephemeralKey });

        const result = await engine.evaluate(request, ctx(), [makeCredential()], policy);
        expect(result.decisionCapsule?.ephemeral_key).toBeTruthy();
        expect(typeof result.decisionCapsule?.ephemeral_key).toBe('object');
    });

    it('throws SECURITY_ERROR when ephemeral key export fails', async () => {
        const ephemeralKey = await globalThis.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        const exportSpy = vi.spyOn(globalThis.crypto.subtle, 'exportKey').mockRejectedValueOnce(
            new Error('DOMException: not extractable')
        );

        const policy = makePolicy();
        const request = makeRequest({ ephemeralResponseKey: ephemeralKey });

        await expect(engine.evaluate(request, ctx(), [makeCredential()], policy))
            .rejects.toThrow('SECURITY_ERROR');

        exportSpy.mockRestore();
    });
});
