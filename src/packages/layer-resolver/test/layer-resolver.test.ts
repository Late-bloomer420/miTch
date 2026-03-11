/**
 * F-15: layer-resolver tests (previously had 0 coverage)
 */
import { describe, it, expect } from 'vitest';
import {
    ProtectionLayer,
    getInheritedLayers,
    includesLayer,
    getLayerName,
    getMinimumLayerForData,
} from '../src/index.js';

describe('ProtectionLayer enum', () => {
    it('has correct numeric values', () => {
        expect(ProtectionLayer.WELT).toBe(0);
        expect(ProtectionLayer.GRUNDVERSORGUNG).toBe(1);
        expect(ProtectionLayer.VULNERABLE).toBe(2);
    });
});

describe('getInheritedLayers', () => {
    it('WELT includes only itself', () => {
        expect(getInheritedLayers(ProtectionLayer.WELT)).toEqual([ProtectionLayer.WELT]);
    });

    it('GRUNDVERSORGUNG includes WELT and GRUNDVERSORGUNG', () => {
        expect(getInheritedLayers(ProtectionLayer.GRUNDVERSORGUNG)).toEqual([
            ProtectionLayer.WELT,
            ProtectionLayer.GRUNDVERSORGUNG,
        ]);
    });

    it('VULNERABLE includes all three layers', () => {
        expect(getInheritedLayers(ProtectionLayer.VULNERABLE)).toEqual([
            ProtectionLayer.WELT,
            ProtectionLayer.GRUNDVERSORGUNG,
            ProtectionLayer.VULNERABLE,
        ]);
    });
});

describe('includesLayer', () => {
    it('VULNERABLE includes WELT', () => {
        expect(includesLayer(ProtectionLayer.VULNERABLE, ProtectionLayer.WELT)).toBe(true);
    });

    it('VULNERABLE includes GRUNDVERSORGUNG', () => {
        expect(includesLayer(ProtectionLayer.VULNERABLE, ProtectionLayer.GRUNDVERSORGUNG)).toBe(true);
    });

    it('WELT does NOT include GRUNDVERSORGUNG', () => {
        expect(includesLayer(ProtectionLayer.WELT, ProtectionLayer.GRUNDVERSORGUNG)).toBe(false);
    });

    it('GRUNDVERSORGUNG does NOT include VULNERABLE', () => {
        expect(includesLayer(ProtectionLayer.GRUNDVERSORGUNG, ProtectionLayer.VULNERABLE)).toBe(false);
    });

    it('same layer includes itself', () => {
        expect(includesLayer(ProtectionLayer.WELT, ProtectionLayer.WELT)).toBe(true);
        expect(includesLayer(ProtectionLayer.VULNERABLE, ProtectionLayer.VULNERABLE)).toBe(true);
    });
});

describe('getLayerName', () => {
    it('returns human-readable names', () => {
        expect(getLayerName(ProtectionLayer.WELT)).toContain('WELT');
        expect(getLayerName(ProtectionLayer.GRUNDVERSORGUNG)).toContain('GRUNDVERSORGUNG');
        expect(getLayerName(ProtectionLayer.VULNERABLE)).toContain('VULNERABLE');
    });
});

describe('getMinimumLayerForData', () => {
    it('health data requires VULNERABLE', () => {
        expect(getMinimumLayerForData('healthRecord')).toBe(ProtectionLayer.VULNERABLE);
        expect(getMinimumLayerForData('prescription')).toBe(ProtectionLayer.VULNERABLE);
        expect(getMinimumLayerForData('financialData')).toBe(ProtectionLayer.VULNERABLE);
    });

    it('age/education data requires GRUNDVERSORGUNG', () => {
        expect(getMinimumLayerForData('age')).toBe(ProtectionLayer.GRUNDVERSORGUNG);
        expect(getMinimumLayerForData('birthDate')).toBe(ProtectionLayer.GRUNDVERSORGUNG);
        expect(getMinimumLayerForData('education')).toBe(ProtectionLayer.GRUNDVERSORGUNG);
    });

    it('consent/public key requires WELT', () => {
        expect(getMinimumLayerForData('consent')).toBe(ProtectionLayer.WELT);
        expect(getMinimumLayerForData('publicKey')).toBe(ProtectionLayer.WELT);
    });

    it('unknown data type defaults to WELT', () => {
        expect(getMinimumLayerForData('somethingUnknown')).toBe(ProtectionLayer.WELT);
    });
});
