import { describe, it, expect } from 'vitest';
import { PACKAGE_NAME } from '../index';

describe('@askmi/evidence package', () => {
  it('exposes its package name', () => {
    expect(PACKAGE_NAME).toBe('@askmi/evidence');
  });
});
