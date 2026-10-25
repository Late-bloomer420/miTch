import { describe, it, expect } from 'vitest';
import { validateManifest } from '../manifest';
import type { EvidenceClaim } from '../types';

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
  it('accepts a valid non-residual claim', () => {
    expect(() => validateManifest([valid])).not.toThrow();
  });
  it('accepts a residual claim with empty test fields', () => {
    expect(() => validateManifest([residual])).not.toThrow();
  });
  it('throws when a non-residual claim is missing testFile', () => {
    expect(() => validateManifest([{ ...valid, testFile: '' }])).toThrow(/testFile/);
  });
  it('throws on an unknown category', () => {
    expect(() => validateManifest([{ ...valid, category: 'bogus' as never }])).toThrow(/category/);
  });
  it('throws on duplicate ids', () => {
    expect(() => validateManifest([valid, valid])).toThrow(/duplicate/i);
  });
});
