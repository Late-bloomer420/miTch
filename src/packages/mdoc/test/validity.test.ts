import { describe, test, expect } from 'vitest';
import { verifyMsoValidity, verifyDocType } from '../src/validity';
import type { ValidityInfo } from '../src/mdoc-types';

// ─── verifyMsoValidity ──────────────────────────────────────────────────────

describe('verifyMsoValidity', () => {
  function makeValidity(overrides?: Partial<ValidityInfo>): ValidityInfo {
    return {
      signed: new Date('2026-01-01T00:00:00Z'),
      validFrom: new Date('2026-01-01T00:00:00Z'),
      validUntil: new Date('2027-01-01T00:00:00Z'),
      ...overrides,
    };
  }

  test('valid: now within range', () => {
    const result = verifyMsoValidity(
      makeValidity(),
      new Date('2026-06-15T00:00:00Z')
    );
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  test('valid: now exactly at validFrom', () => {
    const result = verifyMsoValidity(
      makeValidity(),
      new Date('2026-01-01T00:00:00Z')
    );
    expect(result.valid).toBe(true);
  });

  test('invalid: now before validFrom', () => {
    const result = verifyMsoValidity(
      makeValidity(),
      new Date('2025-12-31T23:59:59Z')
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not yet valid');
  });

  test('invalid: now at validUntil (expired)', () => {
    const result = verifyMsoValidity(
      makeValidity(),
      new Date('2027-01-01T00:00:00Z')
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  test('invalid: now after validUntil', () => {
    const result = verifyMsoValidity(
      makeValidity(),
      new Date('2028-01-01T00:00:00Z')
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  test('invalid: signed after validFrom', () => {
    const result = verifyMsoValidity(
      makeValidity({ signed: new Date('2026-06-01T00:00:00Z') }),
      new Date('2026-06-15T00:00:00Z')
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('signed date is after validFrom');
  });

  test('invalid: validFrom after validUntil', () => {
    const result = verifyMsoValidity(
      makeValidity({
        validFrom: new Date('2028-01-01T00:00:00Z'),
        validUntil: new Date('2027-01-01T00:00:00Z'),
      }),
      new Date('2027-06-15T00:00:00Z')
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('validFrom is after validUntil');
  });

  test('invalid: unparseable date strings', () => {
    const result = verifyMsoValidity(
      { signed: 'not-a-date', validFrom: new Date(), validUntil: new Date() } as unknown as ValidityInfo,
      new Date()
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('invalid dates');
  });

  test('invalid: NaN dates', () => {
    const result = verifyMsoValidity(
      makeValidity({ signed: new Date('invalid') }),
      new Date()
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('invalid dates');
  });

  test('accepts ISO string dates (CBOR decoded format)', () => {
    const result = verifyMsoValidity(
      {
        signed: '2026-01-01T00:00:00Z',
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: '2027-01-01T00:00:00Z',
      } as unknown as ValidityInfo,
      new Date('2026-06-15T00:00:00Z')
    );
    expect(result.valid).toBe(true);
  });

  test('defaults to current time if now not provided', () => {
    // Future validity — should be not-yet-valid when using default now
    const result = verifyMsoValidity(
      makeValidity({
        signed: new Date('2030-01-01T00:00:00Z'),
        validFrom: new Date('2030-01-01T00:00:00Z'),
        validUntil: new Date('2031-01-01T00:00:00Z'),
      })
    );
    expect(result.valid).toBe(false);
  });
});

// ─── verifyDocType ──────────────────────────────────────────────────────────

describe('verifyDocType', () => {
  test('valid: matching docTypes', () => {
    const result = verifyDocType(
      'org.iso.18013.5.1.mDL',
      'org.iso.18013.5.1.mDL'
    );
    expect(result.valid).toBe(true);
  });

  test('invalid: mismatched docTypes', () => {
    const result = verifyDocType(
      'org.iso.18013.5.1.mDL',
      'eu.europa.ec.eudi.pid.1'
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('mismatch');
  });

  test('invalid: empty MSO docType', () => {
    const result = verifyDocType('', 'org.iso.18013.5.1.mDL');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing');
  });

  test('invalid: empty document docType', () => {
    const result = verifyDocType('org.iso.18013.5.1.mDL', '');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing');
  });
});
