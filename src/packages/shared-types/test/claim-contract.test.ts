import { describe, it, expect } from 'vitest';
import {
    resolveClaim,
    CLAIM_CONTRACT_VERSION,
    UnknownClaimError,
    getFormatBinding,
    CLAIM_CONTRACT_SCHEMA_V1,
} from '../src/contracts/claim-contract';

describe('claim-contract / resolveClaim — alias resolution (EUDI-aligned)', () => {
    it('maps disclosed-attribute aliases to canonical "birthdate"', () => {
        for (const alias of ['dateOfBirth', 'birthDate', 'birth_date', 'age']) {
            expect(resolveClaim(alias)).toBe('birthdate');
        }
    });

    it('maps predicate-result aliases to canonical "age_over_18"', () => {
        for (const alias of ['isOver18', 'age >= 18', 'over18', 'age_gte_18']) {
            expect(resolveClaim(alias)).toBe('age_over_18');
        }
    });

    it('returns canonical names unchanged (idempotent)', () => {
        expect(resolveClaim('birthdate')).toBe('birthdate');
        expect(resolveClaim('age_over_18')).toBe('age_over_18');
    });

    it('fails closed on an unknown claim name', () => {
        expect(() => resolveClaim('shoe_size')).toThrow(UnknownClaimError);
    });
});

describe('claim-contract / versioning', () => {
    it('exposes a fixed semver contract version', () => {
        expect(CLAIM_CONTRACT_VERSION).toBe('1.0.0');
    });
});

describe('claim-contract / request schema (JSON-Schema source of truth)', () => {
    it('is a Draft 2020-12 schema versioned to the contract', () => {
        expect(CLAIM_CONTRACT_SCHEMA_V1.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
        expect(CLAIM_CONTRACT_SCHEMA_V1.$id).toMatch(/\/claim-contract\/v1$/);
    });

    it('pins the contractVersion via a const matching CLAIM_CONTRACT_VERSION', () => {
        const props = CLAIM_CONTRACT_SCHEMA_V1.properties as Record<string, { const?: string }>;
        expect(props.contractVersion.const).toBe(CLAIM_CONTRACT_VERSION);
    });

    it('requires a non-empty claims array and forbids extra properties', () => {
        expect(CLAIM_CONTRACT_SCHEMA_V1.required).toEqual(['contractVersion', 'claims']);
        expect(CLAIM_CONTRACT_SCHEMA_V1.additionalProperties).toBe(false);
        const props = CLAIM_CONTRACT_SCHEMA_V1.properties as Record<string, { minItems?: number }>;
        expect(props.claims.minItems).toBe(1);
    });
});

describe('claim-contract / format bindings (EUDI)', () => {
    it('binds age_over_18 to SD-JWT-VC age_equal_or_over nested threshold under urn:eudi:pid:1', () => {
        const b = getFormatBinding('age_over_18', 'sd-jwt-vc');
        expect(b).toEqual({
            format: 'sd-jwt-vc',
            credentialType: 'urn:eudi:pid:1',
            locator: 'age_equal_or_over.18',
            encoding: 'nested-threshold',
        });
    });

    it('binds age_over_18 to a flat mdoc element under eu.europa.ec.eudi.pid.1', () => {
        const b = getFormatBinding('age_over_18', 'mdoc-pid');
        expect(b).toEqual({
            format: 'mdoc-pid',
            credentialType: 'eu.europa.ec.eudi.pid.1',
            locator: 'age_over_18',
            encoding: 'flat-bool',
        });
    });

    it('declares the AV-Profile binding as reserved (mdoc eu.europa.ec.av.1, not yet wired)', () => {
        const b = getFormatBinding('age_over_18', 'av-profile');
        expect(b).toEqual({
            format: 'av-profile',
            credentialType: 'eu.europa.ec.av.1',
            locator: 'age_over_18',
            encoding: 'flat-bool',
            reserved: true,
        });
    });

    it('binds birthdate to SD-JWT-VC "birthdate" and mdoc "birth_date"', () => {
        expect(getFormatBinding('birthdate', 'sd-jwt-vc')?.locator).toBe('birthdate');
        expect(getFormatBinding('birthdate', 'mdoc-pid')?.locator).toBe('birth_date');
    });

    it('reports no birthdate binding for the AV-Profile (data minimization — SHALL NOT include)', () => {
        expect(getFormatBinding('birthdate', 'av-profile')).toBeUndefined();
    });
});
