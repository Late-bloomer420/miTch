import { describe, it, expect } from 'vitest';
import {
  selectPoolMember,
  markMemberUsed,
  poolStats,
  type CredentialPoolMember,
} from '../utils/credential-pool';

const member = (
  id: string,
  issuedAt: string,
  usedAt: string | null = null
): CredentialPoolMember => ({ id, issuedAt, usedAt });

describe('selectPoolMember — single_use', () => {
  it('selects the oldest unused member (deterministic FIFO)', () => {
    const pool = [
      member('c2', '2026-06-08T10:00:01Z'),
      member('c1', '2026-06-08T10:00:00Z'),
      member('c3', '2026-06-08T10:00:02Z'),
    ];
    const sel = selectPoolMember(pool, 'single_use');
    expect(sel.member?.id).toBe('c1');
    expect(sel.exhausted).toBe(false);
  });

  it('skips used members and returns the next unused one', () => {
    const pool = [
      member('c1', '2026-06-08T10:00:00Z', '2026-06-08T11:00:00Z'),
      member('c2', '2026-06-08T10:00:01Z'),
    ];
    expect(selectPoolMember(pool, 'single_use').member?.id).toBe('c2');
  });

  it('reports exhausted (member null) when all members are used', () => {
    const pool = [
      member('c1', '2026-06-08T10:00:00Z', '2026-06-08T11:00:00Z'),
      member('c2', '2026-06-08T10:00:01Z', '2026-06-08T11:05:00Z'),
    ];
    const sel = selectPoolMember(pool, 'single_use');
    expect(sel.member).toBeNull();
    expect(sel.exhausted).toBe(true);
  });

  it('an empty pool is not exhausted (nothing to begin with)', () => {
    const sel = selectPoolMember([], 'single_use');
    expect(sel.member).toBeNull();
    expect(sel.exhausted).toBe(false);
  });

  it('single-credential pool: selects it, then exhausts after use', () => {
    let pool = [member('only', '2026-06-08T10:00:00Z')];
    const first = selectPoolMember(pool, 'single_use');
    expect(first.member?.id).toBe('only');

    pool = markMemberUsed(pool, 'only', '2026-06-08T12:00:00Z');
    const second = selectPoolMember(pool, 'single_use');
    expect(second.member).toBeNull();
    expect(second.exhausted).toBe(true);
  });

  it('defaults to single_use when no policy is given', () => {
    const pool = [member('c1', '2026-06-08T10:00:00Z', '2026-06-08T11:00:00Z')];
    expect(selectPoolMember(pool).exhausted).toBe(true);
  });
});

describe('selectPoolMember — reuse', () => {
  it('always returns the oldest member and is never exhausted', () => {
    const pool = [
      member('c1', '2026-06-08T10:00:00Z', '2026-06-08T11:00:00Z'),
      member('c2', '2026-06-08T10:00:01Z', '2026-06-08T11:05:00Z'),
    ];
    const sel = selectPoolMember(pool, 'reuse');
    expect(sel.member?.id).toBe('c1');
    expect(sel.exhausted).toBe(false);
  });

  it('returns null member for an empty pool, still not exhausted', () => {
    expect(selectPoolMember([], 'reuse')).toEqual({ member: null, exhausted: false });
  });
});

describe('markMemberUsed', () => {
  it('marks the target member used without mutating the input', () => {
    const pool = [member('c1', '2026-06-08T10:00:00Z')];
    const next = markMemberUsed(pool, 'c1', '2026-06-08T12:00:00Z');
    expect(next[0].usedAt).toBe('2026-06-08T12:00:00Z');
    // original untouched (immutability)
    expect(pool[0].usedAt).toBeNull();
    expect(next).not.toBe(pool);
  });

  it('is idempotent — an already-used member keeps its first usedAt', () => {
    const pool = [member('c1', '2026-06-08T10:00:00Z', '2026-06-08T11:00:00Z')];
    const next = markMemberUsed(pool, 'c1', '2026-06-08T12:00:00Z');
    expect(next[0].usedAt).toBe('2026-06-08T11:00:00Z');
  });

  it('leaves the list unchanged for an unknown id', () => {
    const pool = [member('c1', '2026-06-08T10:00:00Z')];
    const next = markMemberUsed(pool, 'nope', '2026-06-08T12:00:00Z');
    expect(next[0].usedAt).toBeNull();
  });
});

describe('poolStats', () => {
  it('counts total, used and available', () => {
    const pool = [
      member('c1', '2026-06-08T10:00:00Z', '2026-06-08T11:00:00Z'),
      member('c2', '2026-06-08T10:00:01Z'),
      member('c3', '2026-06-08T10:00:02Z'),
    ];
    expect(poolStats(pool)).toEqual({ total: 3, used: 1, available: 2 });
  });

  it('handles an empty pool', () => {
    expect(poolStats([])).toEqual({ total: 0, used: 0, available: 0 });
  });
});
