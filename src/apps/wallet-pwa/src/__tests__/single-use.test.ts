/**
 * Single-Use Credential wiring — pure helpers (Proof-Randomization, U-12 increment 4)
 *
 * These cover the honesty-critical decisions: when a presentation counts as
 * single-use, when a credential still needs consuming, the immutable consume
 * transition, and fail-closed exclusion of already-consumed members from
 * future selection. The imperative storage/audit wiring lives in WalletService.
 */

import { describe, it, expect } from 'vitest';
import type { StoredCredentialMetadata } from '@askmi/shared-types';
import {
  isSingleUsePresentation,
  needsConsumption,
  markConsumed,
  selectablePresentationCredentials,
} from '../utils/single-use';

function meta(over: Partial<StoredCredentialMetadata>): StoredCredentialMetadata {
  return {
    id: 'cred-1',
    issuer: 'did:askmi:issuer',
    type: ['AgeCredential'],
    issuedAt: '2026-01-01T00:00:00.000Z',
    claims: ['birthDate'],
    ...over,
  };
}

describe('single-use — isSingleUsePresentation', () => {
  it('is true when any presented credential is single-use', () => {
    expect(isSingleUsePresentation([meta({ singleUse: false }), meta({ singleUse: true })])).toBe(
      true
    );
  });

  it('is false when no presented credential is single-use', () => {
    expect(isSingleUsePresentation([meta({}), meta({ singleUse: false })])).toBe(false);
  });

  it('ignores null/undefined entries (skipped requirements)', () => {
    expect(isSingleUsePresentation([null, undefined, meta({ singleUse: true })])).toBe(true);
    expect(isSingleUsePresentation([null, undefined])).toBe(false);
  });
});

describe('single-use — needsConsumption', () => {
  it('true only for an unconsumed single-use credential', () => {
    expect(needsConsumption(meta({ singleUse: true }))).toBe(true);
  });

  it('false for a reusable credential', () => {
    expect(needsConsumption(meta({ singleUse: false }))).toBe(false);
    expect(needsConsumption(meta({}))).toBe(false);
  });

  it('false once already consumed (idempotent)', () => {
    expect(needsConsumption(meta({ singleUse: true, consumedAt: '2026-06-08T00:00:00.000Z' }))).toBe(
      false
    );
  });
});

describe('single-use — markConsumed', () => {
  it('marks an unconsumed single-use credential consumed and dispensed', () => {
    const ts = '2026-06-08T10:00:00.000Z';
    const out = markConsumed(meta({ singleUse: true, status: 'active' }), ts);
    expect(out.consumedAt).toBe(ts);
    expect(out.status).toBe('dispensed');
  });

  it('does not mutate the input', () => {
    const input = meta({ singleUse: true });
    const out = markConsumed(input, '2026-06-08T10:00:00.000Z');
    expect(input.consumedAt).toBeUndefined();
    expect(out).not.toBe(input);
  });

  it('is idempotent — keeps the original consumedAt', () => {
    const first = '2026-06-08T10:00:00.000Z';
    const out = markConsumed(meta({ singleUse: true, consumedAt: first }), '2026-06-08T11:00:00.000Z');
    expect(out.consumedAt).toBe(first);
  });

  it('leaves a reusable credential untouched', () => {
    const input = meta({ singleUse: false });
    expect(markConsumed(input, '2026-06-08T10:00:00.000Z')).toBe(input);
  });
});

describe('single-use — selectablePresentationCredentials', () => {
  it('excludes consumed single-use credentials (fail-closed non-reuse)', () => {
    const reusable = meta({ id: 'reuse', singleUse: false });
    const freshSingle = meta({ id: 'fresh', singleUse: true });
    const spent = meta({ id: 'spent', singleUse: true, consumedAt: '2026-06-08T00:00:00.000Z' });
    const out = selectablePresentationCredentials([reusable, freshSingle, spent]);
    expect(out.map((m) => m.id)).toEqual(['reuse', 'fresh']);
  });

  it('keeps everything when nothing is consumed', () => {
    const list = [meta({ id: 'a' }), meta({ id: 'b', singleUse: true })];
    expect(selectablePresentationCredentials(list)).toHaveLength(2);
  });
});
