/**
 * Tests: Pairwise DID in Policy Engine Proof Generation (U-05)
 *
 * Verifies that ALLOW/PROMPT decisions include a fresh pairwise did:peer:0
 * and a valid proof, while DENY decisions do not.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine, type EvaluationContext } from '../engine';
import { verifyPairwiseDIDProof } from '@mitch/shared-crypto';
import { ProtectionLayer } from '@mitch/layer-resolver';
import type { PolicyManifest, VerifierRequest, StoredCredentialMetadata } from '@mitch/shared-types';

// ─── Shared fixtures ─────────────────────────────────────────────────────────

const makePolicy = (overrides: Partial<PolicyManifest> = {}): PolicyManifest => ({
    version: '1.0.0',
    trustedIssuers: [
        { did: 'did:example:gov', name: 'Gov', credentialTypes: ['IDCredential'] },
    ],
    rules: [
        {
            id: 'test-rule',
            verifierPattern: 'did:example:verifier-*',
            minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
            allowedClaims: ['age'],
            provenClaims: ['isOver18'],
            requiresTrustedIssuer: true,
            maxCredentialAgeDays: 365,
            requiresUserConsent: false,
            priority: 10,
        },
    ],
    globalSettings: { blockUnknownVerifiers: true },
    ...overrides,
});

const makeCredential = (): StoredCredentialMetadata => ({
    id: 'cred-001',
    type: ['IDCredential'],
    issuer: 'did:example:gov',
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    claims: ['age', 'isOver18'],
});

const makeRequest = (overrides: Partial<VerifierRequest> = {}): VerifierRequest => ({
    verifierId: 'did:example:verifier-liquor-store',
    requestedClaims: ['age'],
    requestedProvenClaims: ['isOver18'],
    requirements: [
        { credentialType: 'IDCredential', requestedClaims: ['age'], requestedProvenClaims: ['isOver18'] },
    ],
    nonce: 'session-nonce-abc',
    ...overrides,
});

const makeContext = (): EvaluationContext => ({
    timestamp: Date.now(),
    userDID: 'did:example:alice',
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('U-05: Pairwise DID in Policy Engine Proof Generation', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    it('ALLOW verdict includes a pairwise_did starting with did:peer:0z', async () => {
        const result = await engine.evaluate(
            makeRequest(),
            makeContext(),
            [makeCredential()],
            makePolicy()
        );

        expect(result.verdict).toBe('ALLOW');
        expect(result.decisionCapsule).toBeDefined();
        expect(result.decisionCapsule!.pairwise_did).toMatch(/^did:peer:0z/);
    });

    it('ALLOW verdict includes a non-empty pairwise_proof (hex)', async () => {
        const result = await engine.evaluate(
            makeRequest(),
            makeContext(),
            [makeCredential()],
            makePolicy()
        );

        const proof = result.decisionCapsule!.pairwise_proof;
        expect(typeof proof).toBe('string');
        expect(proof!.length).toBeGreaterThan(0);
        // Hex string — only 0-9 a-f
        expect(proof).toMatch(/^[0-9a-f]+$/);
    });

    it('pairwise_proof is a valid ECDSA signature over decision_id', async () => {
        const result = await engine.evaluate(
            makeRequest(),
            makeContext(),
            [makeCredential()],
            makePolicy()
        );

        const capsule = result.decisionCapsule!;
        const did = capsule.pairwise_did!;
        const proofHex = capsule.pairwise_proof!;

        // Convert hex → Uint8Array
        const sigBytes = new Uint8Array(
            proofHex.match(/.{2}/g)!.map(h => parseInt(h, 16))
        );
        const dataBytes = new TextEncoder().encode(capsule.decision_id);

        const valid = await verifyPairwiseDIDProof(did, dataBytes, sigBytes);
        expect(valid).toBe(true);
    });

    it('Two ALLOW verdicts for same verifier produce different pairwise_did (per-session uniqueness)', async () => {
        const req = makeRequest();

        const r1 = await engine.evaluate(req, makeContext(), [makeCredential()], makePolicy());
        const r2 = await engine.evaluate(req, makeContext(), [makeCredential()], makePolicy());

        expect(r1.decisionCapsule!.pairwise_did).toBeDefined();
        expect(r2.decisionCapsule!.pairwise_did).toBeDefined();
        // Phase 1: keys are random → DIDs must differ
        expect(r1.decisionCapsule!.pairwise_did).not.toBe(r2.decisionCapsule!.pairwise_did);
    });

    it('Two ALLOW verdicts for different verifiers produce different pairwise_did', async () => {
        const req1 = makeRequest({ verifierId: 'did:example:verifier-liquor-store' });
        const req2 = makeRequest({ verifierId: 'did:example:verifier-pharmacy' });

        const r1 = await engine.evaluate(req1, makeContext(), [makeCredential()], makePolicy());
        const r2 = await engine.evaluate(req2, makeContext(), [makeCredential()], makePolicy());

        expect(r1.decisionCapsule!.pairwise_did).not.toBe(r2.decisionCapsule!.pairwise_did);
    });

    it('DENY verdict does NOT include pairwise_did', async () => {
        const result = await engine.evaluate(
            makeRequest({ verifierId: 'did:example:unknown-verifier' }),
            makeContext(),
            [makeCredential()],
            makePolicy() // blockUnknownVerifiers: true — will DENY
        );

        expect(result.verdict).toBe('DENY');
        // No capsule generated for DENY with unknown verifier
        // (or if capsule exists, no pairwise_did)
        if (result.decisionCapsule) {
            expect(result.decisionCapsule.pairwise_did).toBeUndefined();
        }
    });

    it('PROMPT verdict also includes pairwise_did', async () => {
        const promptPolicy = makePolicy({
            rules: [
                {
                    id: 'consent-rule',
                    verifierPattern: 'did:example:verifier-*',
                    minimumLayer: ProtectionLayer.GRUNDVERSORGUNG,
                    allowedClaims: ['age'],
                    provenClaims: ['isOver18'],
                    requiresTrustedIssuer: true,
                    requiresUserConsent: true, // Force PROMPT
                    priority: 10,
                },
            ],
        });

        const result = await engine.evaluate(
            makeRequest(),
            makeContext(),
            [makeCredential()],
            promptPolicy
        );

        expect(result.verdict).toBe('PROMPT');
        expect(result.decisionCapsule!.pairwise_did).toMatch(/^did:peer:0z/);
    });
});
