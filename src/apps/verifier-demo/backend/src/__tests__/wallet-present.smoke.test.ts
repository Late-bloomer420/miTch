/**
 * Sprint 1A: Pilot Flow Smoke Test
 *
 * Promotes the manual five-scenario `/wallet-present` matrix
 * (docs/qa/PILOT_FLOW_RERUN_2026-06-04.md) into an automated smoke test,
 * so pilot-flow evidence no longer depends on manual PowerShell reruns.
 *
 * Each scenario asserts both sides of the privacy-by-design guarantee:
 *   1. the requested claims ARE selectively disclosed, and
 *   2. the sensitive claims the verifier did NOT ask for are withheld.
 *
 * The revoked scenario asserts fail-closed denial (403 REVOKED).
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { app } from '../app';
import { statusResolver, trustListResolver } from '@askmi/shared-crypto';

// ─── Fixtures ────────────────────────────────────────────────────────────────

// Trust list that recognises the demo issuer + verifier used by /wallet-present.
const MOCK_TSL = {
    id: 'pilot-smoke-tsl',
    version: '1.0.0',
    validUntil: '2030-01-01T00:00:00Z',
    issuers: ['https://issuer.mitch.demo'],
    verifiers: ['did:mitch:verifier-liquor-store'],
};

// StatusList2021 fixture with bit index 42 set (the index demo-flow embeds for
// the revoked scenario — see demo-flow.ts buildSDJWTPresentation `idx: 42`).
function buildRevokedStatusList() {
    const bitstring = new Uint8Array(64);
    bitstring[5] = 0b00100000; // bit 42 set
    return {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: 'http://localhost:3005/status-list/1',
        type: ['VerifiableCredential', 'StatusList2021Credential'],
        issuer: 'https://issuer.mitch.demo',
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
            id: 'http://localhost:3005/status-list/1#list',
            type: 'StatusList2021',
            statusPurpose: 'revocation',
            encodedList: Buffer.from(bitstring).toString('base64'),
        },
    };
}

// Expected selective-disclosure outcome per scenario, mirroring the QA matrix.
const DISCLOSURE_MATRIX: Record<string, { disclosed: string[]; withheld: string[] }> = {
    'liquor-store': {
        disclosed: ['age'],
        withheld: ['name', 'address', 'nationalId', 'dateOfBirth'],
    },
    'doctor-login': {
        disclosed: ['age', 'role', 'licenseId'],
        withheld: ['salary', 'homeAddress', 'employer'],
    },
    'ehds-er': {
        disclosed: ['bloodGroup', 'allergies', 'emergencyContacts'],
        withheld: ['activeProblems', 'diagnosis', 'geneticData', 'insuranceId'],
    },
    'pharmacy': {
        disclosed: ['medication', 'dosageInstruction', 'refillsRemaining'],
        withheld: ['diagnosis', 'insuranceId', 'geneticData'],
    },
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('/wallet-present pilot flow smoke test', () => {
    beforeAll(() => {
        // Avoid file I/O for verifier keys (see app.ts getVerifierKeys).
        process.env.MITCH_TEST_MODE = '1';

        // Trust-list resolver answers with the demo issuer/verifier for every scenario.
        const tslFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => MOCK_TSL });
        trustListResolver.setFetch(tslFetch as never);
        trustListResolver.clearCache();
    });

    beforeEach(async () => {
        await request(app).post('/reset');
    });

    for (const [scenario, { disclosed, withheld }] of Object.entries(DISCLOSURE_MATRIX)) {
        it(`accepts "${scenario}" and discloses only the requested claims`, async () => {
            const res = await request(app).post('/wallet-present').send({ scenarioId: scenario });

            expect(res.status).toBe(200);
            expect(res.body.ok).toBe(true);
            expect(res.body.disclosedClaims).toBeDefined();

            const keys = Object.keys(res.body.disclosedClaims);
            for (const claim of disclosed) {
                expect(keys, `expected "${claim}" disclosed for ${scenario}`).toContain(claim);
            }
            for (const claim of withheld) {
                expect(keys, `expected "${claim}" withheld for ${scenario}`).not.toContain(claim);
            }
        });
    }

    describe('revoked scenario (fail-closed)', () => {
        beforeEach(() => {
            const statusFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => buildRevokedStatusList() });
            statusResolver.setFetch(statusFetch as never);
            vi.stubGlobal('fetch', statusFetch);
        });

        afterEach(() => {
            vi.unstubAllGlobals();
        });

        it('denies a revoked credential with 403 REVOKED', async () => {
            const res = await request(app).post('/wallet-present').send({ scenarioId: 'revoked' });

            expect(res.status).toBe(403);
            expect(res.body.ok).toBe(false);
            expect(res.body.errors).toBeDefined();
            const errorText = JSON.stringify(res.body.errors).toLowerCase();
            expect(errorText).toMatch(/revok/);
        });
    });
});
