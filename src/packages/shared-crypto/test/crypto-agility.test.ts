import { describe, it, expect } from 'vitest';
import {
    negotiateAlgorithm,
    getMigrationPlan,
    ALGORITHM_REGISTRY,
    CRYPTO_PROFILES,
} from '../src/crypto-agility';

describe('negotiateAlgorithm', () => {
    it('selects highest-priority common algorithm', () => {
        const r = negotiateAlgorithm({
            category: 'signing',
            supported: ['ES256', 'RS256', 'ML-DSA-44'],
        });
        expect(r.ok).toBe(true);
        if (r.ok) {
            // ML-DSA-44 has priority 95, ES256 has 80
            expect(r.negotiated).toBe('ML-DSA-44');
        }
    });

    it('respects requirePQC=true', () => {
        const r = negotiateAlgorithm({
            category: 'signing',
            supported: ['ES256', 'ES384'],
            requirePQC: true,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('NO_PQC_ALGORITHM');
    });

    it('selects PQC algorithm when available and required', () => {
        const r = negotiateAlgorithm({
            category: 'signing',
            supported: ['ES256', 'ML-DSA-65'],
            requirePQC: true,
        });
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.negotiated).toBe('ML-DSA-65');
    });

    it('skips deprecated algorithms', () => {
        const r = negotiateAlgorithm({
            category: 'signing',
            supported: ['RS256'], // RS256 is deprecated
        });
        expect(r.ok).toBe(false);
    });

    it('respects minSecurityLevel', () => {
        const r = negotiateAlgorithm({
            category: 'signing',
            supported: ['ES256', 'ES384', 'ES512'],
            minSecurityLevel: 5,
        });
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.negotiated).toBe('ES512');
    });

    it('returns error when no compatible algorithm found', () => {
        const r = negotiateAlgorithm({
            category: 'signing',
            supported: ['SOME-UNKNOWN-ALG'],
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe('NO_COMPATIBLE_ALGORITHM');
    });
});

describe('getMigrationPlan', () => {
    it('returns migration plan for deprecated RS256', () => {
        const plan = getMigrationPlan('RS256');
        expect(plan).not.toBeNull();
        expect(plan!.urgency).toBe('immediate');
        expect(plan!.current).toBe('RS256');
    });

    it('returns migration plan for active but non-PQC ES256', () => {
        const plan = getMigrationPlan('ES256');
        expect(plan).not.toBeNull();
        expect(plan!.urgency).toBe('planned');
        expect(plan!.steps.length).toBeGreaterThan(0);
    });

    it('returns null for PQC-ready algorithm', () => {
        const plan = getMigrationPlan('ML-DSA-65');
        expect(plan).toBeNull();
    });

    it('returns null for unknown algorithm', () => {
        const plan = getMigrationPlan('UNKNOWN-ALG');
        expect(plan).toBeNull();
    });
});

describe('ALGORITHM_REGISTRY', () => {
    it('contains PQC-ready algorithms', () => {
        const pqc = ALGORITHM_REGISTRY.filter(e => e.pqcReady);
        expect(pqc.length).toBeGreaterThan(0);
    });

    it('ML-DSA algorithms are pqc-candidate', () => {
        const mlDSA = ALGORITHM_REGISTRY.filter(e => e.id.startsWith('ML-DSA'));
        expect(mlDSA.every(e => e.status === 'pqc-candidate')).toBe(true);
    });

    it('SHA3-256 is PQC ready', () => {
        const sha3 = ALGORITHM_REGISTRY.find(e => e.id === 'SHA3-256');
        expect(sha3?.pqcReady).toBe(true);
    });
});

describe('CRYPTO_PROFILES', () => {
    it('hybrid profile uses PQC for signing', () => {
        expect(CRYPTO_PROFILES.hybrid.signingAlgorithm).toBe('ES256+ML-DSA-44');
    });

    it('pqc-only profile uses ML-DSA', () => {
        expect(CRYPTO_PROFILES['pqc-only'].signingAlgorithm).toBe('ML-DSA-65');
    });

    it('classical profile uses ES256', () => {
        expect(CRYPTO_PROFILES.classical.signingAlgorithm).toBe('ES256');
    });
});
