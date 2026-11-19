import { describe, it, expect } from 'vitest';
import { validateManifest } from '../manifest';
import type { EvidenceCategory, EvidenceClaim } from '../types';

const valid: EvidenceClaim = {
  id: 'T-1', claim: 'x', category: 'stride',
  pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine',
  testFile: 'src/__tests__/input-validation.test.ts',
};
const residual: EvidenceClaim = {
  id: 'GAP-1', claim: 'RAM wipe', category: 'fail-closed',
  pnpmFilter: '', packageDir: '', testFile: '', residual: { reason: 'browser limit' },
};

describe('validateManifest', () => {
  it('accepts an empty manifest', () => {
    expect(() => validateManifest([])).not.toThrow();
  });
  it.each<EvidenceCategory>(['stride', 'fail-closed', 'gdpr', 'eudi-cir', 'unlinkability'])(
    'accepts a runnable claim in the %s category',
    (category) => {
      expect(() => validateManifest([{ ...valid, category }])).not.toThrow();
    }
  );
  it('accepts the same test target for distinct claim IDs', () => {
    expect(() => validateManifest([valid, { ...valid, id: 'T-2' }])).not.toThrow();
  });
  it('accepts a residual claim with empty test fields', () => {
    expect(() => validateManifest([residual])).not.toThrow();
  });
  it.each(['pnpmFilter', 'packageDir', 'testFile'] as const)(
    'rejects a runnable claim missing %s even after a residual',
    (field) => {
      expect(() => validateManifest([residual, { ...valid, [field]: '' }])).toThrow(
        `manifest: ${valid.id} missing ${field}`
      );
    }
  );
  describe.each([valid, residual])('common checks for $id', (entry) => {
    it('rejects an empty ID', () => {
      expect(() => validateManifest([{ ...entry, id: '' }])).toThrow('missing id');
    });
    it('rejects empty claim text', () => {
      expect(() => validateManifest([{ ...entry, claim: '' }])).toThrow(
        `${entry.id} missing claim text`
      );
    });
    it('rejects an unknown category', () => {
      const category = 'bogus' as EvidenceCategory;
      expect(() => validateManifest([{ ...entry, category }])).toThrow(
        `${entry.id} unknown category bogus`
      );
    });
  });
  it('rejects a runnable claim that reuses a residual ID', () => {
    expect(() => validateManifest([residual, { ...valid, id: residual.id }])).toThrow(
      `duplicate id ${residual.id}`
    );
  });
  it('rejects duplicate IDs among runnable claims', () => {
    expect(() => validateManifest([valid, { ...valid }])).toThrow(`duplicate id ${valid.id}`);
  });
});
