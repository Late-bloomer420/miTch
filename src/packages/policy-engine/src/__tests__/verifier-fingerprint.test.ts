/**
 * Tests: S-01 — Verifier Fingerprint (Kryptografische Verifier-Identität)
 *
 * Attack pattern: Fake Verifier Spoofing
 * Defense: If a rule has verifier_fingerprint set, any mismatch or
 *          missing fingerprint escalates to PROMPT — never auto-ALLOW.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine, ReasonCode, type EvaluationContext } from '../engine';
import { ProtectionLayer } from '@mitch/layer-resolver';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';

const KNOWN_FINGERPRINT = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const FAKE_FINGERPRINT  = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

const makePolicy = (withFingerprint: boolean): PolicyManifest => ({
    version: '1.0.0',
    trustedIssuers: [
        { did: 'did:example:gov', name: 'Gov', credentialTypes: ['IDCredential'] },
    ],
    rules: [
        {
            id: 'fingerprint-rule',
            verifierPattern: 'did:example:pharmacy',
            minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
            allowedClaims: ['age'],
            requiresTrustedIssuer: true,
            requiresUserConsent: false,
            priority: 10,
            ...(withFingerprint ? { verifier_fingerprint: KNOWN_FINGERPRINT } : {}),
        },
    ],
    globalSettings: { blockUnknownVerifiers: true },
});

const makeCredential = (): StoredCredentialMetadata => ({
    id: 'cred-001',
    type: ['IDCredential'],
    issuer: 'did:example:gov',
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    claims: ['age'],
});

const makeRequest = (fingerprint?: string): VerifierRequest => ({
    verifierId: 'did:example:pharmacy',
    requestedClaims: ['age'],
    requirements: [
        { credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: [] },
    ],
    nonce: 'nonce-001',
    ...(fingerprint !== undefined ? { verifier_fingerprint: fingerprint } : {}),
});

const ctx = (): EvaluationContext => ({
    timestamp: Date.now(),
    userDID: 'did:example:alice',
});

describe('S-01: Verifier Fingerprint', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('ALLOW when fingerprint matches', async () => {
        const result = await engine.evaluate(
            makeRequest(KNOWN_FINGERPRINT),
            ctx(),
            [makeCredential()],
            makePolicy(true)
        );
        expect(result.verdict).toBe('ALLOW');
        expect(result.reasonCodes).not.toContain(ReasonCode.FINGERPRINT_MISMATCH);
    });

    it('PROMPT (not ALLOW) when fingerprint is absent and rule requires one', async () => {
        const result = await engine.evaluate(
            makeRequest(/* no fingerprint */),
            ctx(),
            [makeCredential()],
            makePolicy(true)
        );
        expect(result.verdict).toBe('PROMPT');
        expect(result.reasonCodes).toContain(ReasonCode.FINGERPRINT_MISMATCH);
    });

    it('PROMPT (not ALLOW) when fingerprint does not match (fake verifier spoofing)', async () => {
        const result = await engine.evaluate(
            makeRequest(FAKE_FINGERPRINT),
            ctx(),
            [makeCredential()],
            makePolicy(true)
        );
        expect(result.verdict).toBe('PROMPT');
        expect(result.reasonCodes).toContain(ReasonCode.FINGERPRINT_MISMATCH);
    });

    it('ALLOW when rule has no fingerprint (backward compatible)', async () => {
        const result = await engine.evaluate(
            makeRequest(/* no fingerprint */),
            ctx(),
            [makeCredential()],
            makePolicy(false) // no verifier_fingerprint in rule
        );
        expect(result.verdict).toBe('ALLOW');
    });

    it('PROMPT is returned — not DENY — on mismatch (user can still confirm)', async () => {
        const result = await engine.evaluate(
            makeRequest(FAKE_FINGERPRINT),
            ctx(),
            [makeCredential()],
            makePolicy(true)
        );
        // Must be PROMPT so the user can confirm — not a hard DENY
        expect(result.verdict).toBe('PROMPT');
        expect(result.verdict).not.toBe('DENY');
    });
});
