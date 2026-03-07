/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * T-01: OID4VP End-to-End Protocol Flow Tests
 *
 * Tests the complete protocol stack:
 *   Verifier → OID4VP Request → Wallet → SD-JWT VC + KB-JWT → Verifier Validates
 *
 * All crypto operations are real (no mocks).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
    buildOID4VPRequest,
    buildSDJWTPresentation,
    validateSDJWTPresentation,
    buildSessionCleanup,
    SCENARIO_PRESENTATION_DEFINITIONS,
    SCENARIO_VCT,
} from '../demo-flow';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const VERIFIER_CLIENT_ID = 'did:mitch:verifier-test';
const REDIRECT_URI = 'https://verifier.mitch.test/present';
const ISSUER_DID = 'https://issuer.mitch.test';

const AGE_CLAIMS = { age: 24, birthDate: '2000-01-01', name: 'Max Mustermann' };
const DOCTOR_CLAIMS = { age: 35, role: 'Surgeon', licenseId: 'MED-998877', salary: 'redacted' };
const EHDS_CLAIMS = { bloodGroup: 'A+', allergies: 'Penicillin', emergencyContacts: '+49-151-0100', diagnosis: '[private]' };

async function makeIssuerKeyPair(): Promise<CryptoKeyPair> {
    return globalThis.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
}

async function makeHolderKeyPair(): Promise<CryptoKeyPair> {
    return globalThis.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
}

// ─── T-01a: Happy Path — Liquor Store ────────────────────────────────────────

describe('T-01: OID4VP E2E — Liquor Store (age verification)', () => {
    let issuerKeys: CryptoKeyPair;
    let holderKeys: CryptoKeyPair;

    beforeAll(async () => {
        issuerKeys = await makeIssuerKeyPair();
        holderKeys = await makeHolderKeyPair();
    });

    it('W-01: verifier builds a valid OID4VP request', () => {
        const { request, nonce } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });

        expect(request.response_type).toBe('vp_token');
        expect(request.client_id).toBe(VERIFIER_CLIENT_ID);
        expect(request.redirect_uri).toBe(REDIRECT_URI);
        expect(request.nonce).toBe(nonce);
        expect(request.nonce.length).toBe(32); // 16 bytes hex
        expect(request.presentation_definition.id).toBe('pd-age-verification');
        expect(request.presentation_definition.input_descriptors[0].constraints?.limit_disclosure).toBe('required');
    });

    it('W-03: wallet builds SD-JWT VP token with Key Binding', async () => {
        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });

        const result = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'],
            issuerDid: ISSUER_DID,
        });

        expect(result.vpTokenString).toContain('~');
        expect(result.disclosedClaims.age).toBe(24);
        // birthDate must NOT be disclosed (not in PD)
        expect(result.disclosedClaims.birthDate).toBeUndefined();
        expect(result.disclosedClaims.name).toBeUndefined();
        expect(result.presentationSubmission.definition_id).toBe('pd-age-verification');
    });

    it('W-04: verifier validates VP token and extracts disclosed claims', async () => {
        const { request, nonce } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });
        // Keep nonce (stored in nonceStore in production)
        expect(nonce.length).toBeGreaterThan(0);

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'],
            issuerDid: ISSUER_DID,
        });

        const validation = await validateSDJWTPresentation({
            vpTokenString,
            presentationSubmission,
            request,
            issuerPublicKey: issuerKeys.publicKey,
        });

        expect(validation.ok).toBe(true);
        expect(validation.errors).toHaveLength(0);
        expect(validation.disclosedClaims?.age).toBe(24);
        // Verify privacy: sensitive fields not disclosed
        expect(validation.disclosedClaims?.birthDate).toBeUndefined();
        expect(validation.disclosedClaims?.name).toBeUndefined();
    });

    it('W-05: session cleanup generates consent receipt + audit entry', async () => {
        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });

        const cleanup = buildSessionCleanup({
            request,
            disclosedClaims: { age: 24 },
            outcome: 'SUCCESS',
        });

        expect(cleanup.consentReceipt.verifier).toBe(VERIFIER_CLIENT_ID);
        expect(cleanup.consentReceipt.claimsShared).toContain('age');
        expect(cleanup.consentReceipt.id).toMatch(/^consent-/);
        expect(cleanup.auditEntry.outcome).toBe('SUCCESS');
        expect(cleanup.auditEntry.claimsShared).toEqual(['age']);
    });
});

// ─── T-01b: Revoked Credential ────────────────────────────────────────────────

describe('T-01: OID4VP E2E — Revoked Credential', () => {
    let issuerKeys: CryptoKeyPair;
    let holderKeys: CryptoKeyPair;

    beforeAll(async () => {
        issuerKeys = await makeIssuerKeyPair();
        holderKeys = await makeHolderKeyPair();
    });

    it('W-04: verifier rejects revoked credential', async () => {
        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'revoked',
        });

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: { age: 24 },
            vct: SCENARIO_VCT['revoked'],
            issuerDid: ISSUER_DID,
            revoked: true, // embed status claim
        });

        const validation = await validateSDJWTPresentation({
            vpTokenString,
            presentationSubmission,
            request,
            issuerPublicKey: issuerKeys.publicKey,
            checkRevocation: true,
        });

        expect(validation.ok).toBe(false);
        expect(validation.errors[0]).toMatch(/revoked/);
    });
});

// ─── T-01c: Tampered VP Token ─────────────────────────────────────────────────

describe('T-01: OID4VP E2E — Tampered VP Token', () => {
    let issuerKeys: CryptoKeyPair;
    let holderKeys: CryptoKeyPair;

    beforeAll(async () => {
        issuerKeys = await makeIssuerKeyPair();
        holderKeys = await makeHolderKeyPair();
    });

    it('W-04: verifier rejects tampered SD-JWT VC', async () => {
        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'],
            issuerDid: ISSUER_DID,
        });

        // Tamper: replace last char of the SD-JWT portion
        const parts = vpTokenString.split('~');
        const tampered = parts[0].slice(0, -4) + 'XXXX';
        const tamperedToken = [tampered, ...parts.slice(1)].join('~');

        const validation = await validateSDJWTPresentation({
            vpTokenString: tamperedToken,
            presentationSubmission,
            request,
            issuerPublicKey: issuerKeys.publicKey,
        });

        expect(validation.ok).toBe(false);
        expect(validation.errors.length).toBeGreaterThan(0);
    });
});

// ─── T-01d: Wrong Audience ────────────────────────────────────────────────────

describe('T-01: OID4VP E2E — Wrong Audience', () => {
    let issuerKeys: CryptoKeyPair;
    let holderKeys: CryptoKeyPair;

    beforeAll(async () => {
        issuerKeys = await makeIssuerKeyPair();
        holderKeys = await makeHolderKeyPair();
    });

    it('W-04: rejects KB-JWT with wrong audience', async () => {
        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'],
            issuerDid: ISSUER_DID,
        });

        // Validate with a DIFFERENT verifier client_id
        const wrongRequest = { ...request, client_id: 'did:mitch:evil-verifier' };
        const validation = await validateSDJWTPresentation({
            vpTokenString,
            presentationSubmission,
            request: wrongRequest,
            issuerPublicKey: issuerKeys.publicKey,
        });

        expect(validation.ok).toBe(false);
        expect(validation.errors.join(' ')).toMatch(/aud/);
    });
});

// ─── T-01e: Expired Nonce / Wrong Nonce ───────────────────────────────────────

describe('T-01: OID4VP E2E — Nonce Mismatch', () => {
    let issuerKeys: CryptoKeyPair;
    let holderKeys: CryptoKeyPair;

    beforeAll(async () => {
        issuerKeys = await makeIssuerKeyPair();
        holderKeys = await makeHolderKeyPair();
    });

    it('W-04: rejects VP token with stale nonce', async () => {
        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'liquor-store',
        });

        const { vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: AGE_CLAIMS,
            vct: SCENARIO_VCT['liquor-store'],
            issuerDid: ISSUER_DID,
        });

        // Validate with a DIFFERENT nonce (simulates nonce rotation / replay)
        const wrongNonceRequest = { ...request, nonce: 'completely-different-nonce-value' };
        const validation = await validateSDJWTPresentation({
            vpTokenString,
            presentationSubmission,
            request: wrongNonceRequest,
            issuerPublicKey: issuerKeys.publicKey,
        });

        expect(validation.ok).toBe(false);
        expect(validation.errors.join(' ')).toMatch(/nonce/);
    });
});

// ─── T-01f: Selective Disclosure (doctor-login) ────────────────────────────────

describe('T-01: OID4VP E2E — Selective Disclosure (doctor-login)', () => {
    it('wallet only discloses role and licenseId, withholds salary', async () => {
        const issuerKeys = await makeIssuerKeyPair();
        const holderKeys = await makeHolderKeyPair();

        const { request } = buildOID4VPRequest({
            verifierClientId: VERIFIER_CLIENT_ID,
            redirectUri: REDIRECT_URI,
            scenarioId: 'doctor-login',
        });

        const { disclosedClaims, vpTokenString, presentationSubmission } = await buildSDJWTPresentation({
            request,
            issuerPrivateKey: issuerKeys.privateKey,
            holderKeyPair: holderKeys,
            claims: DOCTOR_CLAIMS,
            vct: SCENARIO_VCT['doctor-login'],
            issuerDid: ISSUER_DID,
        });

        // Only age, role, licenseId should be disclosed
        expect(disclosedClaims.age).toBe(35);
        expect(disclosedClaims.role).toBe('Surgeon');
        expect(disclosedClaims.licenseId).toBe('MED-998877');
        expect(disclosedClaims.salary).toBeUndefined();

        const validation = await validateSDJWTPresentation({
            vpTokenString,
            presentationSubmission,
            request,
            issuerPublicKey: issuerKeys.publicKey,
        });

        expect(validation.ok).toBe(true);
        expect(validation.disclosedClaims?.salary).toBeUndefined();
    });
});

// ─── T-01g: All Scenario PDs present ─────────────────────────────────────────

describe('T-01: Scenario Presentation Definitions', () => {
    it('all 5 scenarios have valid PDs', () => {
        const scenarioIds = ['liquor-store', 'doctor-login', 'ehds-er', 'pharmacy', 'revoked'];
        for (const id of scenarioIds) {
            const pd = SCENARIO_PRESENTATION_DEFINITIONS[id];
            expect(pd, `Missing PD for scenario ${id}`).toBeDefined();
            expect(pd.input_descriptors.length).toBeGreaterThan(0);
            for (const desc of pd.input_descriptors) {
                expect(desc.constraints?.limit_disclosure).toBe('required');
            }
        }
    });
});
