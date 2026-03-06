import { describe, it, expect } from 'vitest';
import { JurisdictionGate, JURISDICTION_EU_EEA, GDPR_ADEQUATE_COUNTRIES as _GDPR_ADEQUATE_COUNTRIES } from '../jurisdiction';

describe('JurisdictionGate', () => {
    it('allows EU/EEA countries unconditionally', () => {
        const gate = new JurisdictionGate();
        expect(gate.check('AT').allowed).toBe(true);
        expect(gate.check('DE').allowed).toBe(true);
        expect(gate.check('FR').allowed).toBe(true);
    });

    it('denies unknown jurisdiction by default', () => {
        const gate = new JurisdictionGate([], false);
        const r = gate.check('CN');
        expect(r.allowed).toBe(false);
        expect(r.code).toBe('JURISDICTION_NOT_ALLOWED');
    });

    it('allows jurisdiction with explicit allowlist rule', () => {
        const gate = new JurisdictionGate([
            { jurisdiction: 'US', allowed: true, minConsentLevel: 'explicit' }
        ]);
        const r = gate.check('US');
        expect(r.allowed).toBe(true);
        expect(r.requiredConsentLevel).toBe('explicit');
    });

    it('blocks explicitly blocked jurisdiction', () => {
        const gate = new JurisdictionGate([
            { jurisdiction: 'RU', allowed: false }
        ]);
        const r = gate.check('RU');
        expect(r.allowed).toBe(false);
        expect(r.code).toBe('JURISDICTION_BLOCKED');
    });

    it('checkGDPRDataTransfer allows EU-to-EU', () => {
        const gate = new JurisdictionGate();
        const r = gate.checkGDPRDataTransfer('DE');
        expect(r.allowed).toBe(true);
        expect(r.mechanism).toBe('same_jurisdiction');
    });

    it('checkGDPRDataTransfer allows adequate countries', () => {
        const gate = new JurisdictionGate();
        const r = gate.checkGDPRDataTransfer('JP'); // Japan has adequacy
        expect(r.allowed).toBe(true);
        expect(r.mechanism).toBe('adequacy_decision');
    });

    it('checkGDPRDataTransfer blocks non-adequate countries', () => {
        const gate = new JurisdictionGate();
        const r = gate.checkGDPRDataTransfer('CN');
        expect(r.allowed).toBe(false);
        expect(r.reason).toContain('No GDPR adequacy');
    });

    it('getGDPRStatus for EU member', () => {
        const gate = new JurisdictionGate();
        const s = gate.getGDPRStatus('AT');
        expect(s.applies).toBe(true);
        expect(s.adequacy).toBe('eu_member');
    });

    it('isValidCode validates ISO 3166 codes', () => {
        expect(JurisdictionGate.isValidCode('AT')).toBe(true);
        expect(JurisdictionGate.isValidCode('EU')).toBe(true);
        expect(JurisdictionGate.isValidCode('austria')).toBe(false);
        expect(JurisdictionGate.isValidCode('A')).toBe(false);
    });

    it('intersectWithGeoScope filters allowed countries', () => {
        const gate = new JurisdictionGate([], false);
        const result = gate.intersectWithGeoScope(['AT', 'DE', 'CN', 'RU']);
        expect(result).toContain('AT');
        expect(result).toContain('DE');
        expect(result).not.toContain('CN');
        expect(result).not.toContain('RU');
    });
});

describe('JURISDICTION_EU_EEA', () => {
    it('contains expected members', () => {
        expect(JURISDICTION_EU_EEA.has('AT')).toBe(true);
        expect(JURISDICTION_EU_EEA.has('DE')).toBe(true);
        expect(JURISDICTION_EU_EEA.has('US')).toBe(false);
    });
});
