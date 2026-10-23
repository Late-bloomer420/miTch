import { describe, expect, it } from 'vitest';
import {
  Mapping,
  analyzeComposition,
  findDuplicateKeys,
  verifyBijectionPair,
  verifyTrustEquivalence,
} from '../src/index.js';

describe('findDuplicateKeys (injectivity guard for credential IDs)', () => {
  it('finds the first counterexample', () => {
    const finding = findDuplicateKeys(
      [{ id: 'cred-1' }, { id: 'cred-2' }, { id: 'cred-1' }],
      (c) => c.id
    );
    expect(finding).not.toBeNull();
    expect(finding!.key).toBe('cred-1');
    expect(finding!.offenders).toHaveLength(2);
  });

  it('returns null when key assignment is injective', () => {
    expect(findDuplicateKeys([{ id: 'a' }, { id: 'b' }], (c) => c.id)).toBeNull();
  });
});

describe('analyzeComposition (selective-disclosure pipeline analysis)', () => {
  const credentials = new Set(['gov-age', 'uni-student', 'bank-kyc']);
  const disclosed = new Set(['age:24', 'student:true', 'kyc:verified']);
  const proof = new Set(['18+', 'enrolled', 'verified']);

  const f = Mapping.fromPairs(credentials, disclosed, [
    ['gov-age', 'age:24'],
    ['uni-student', 'student:true'],
    ['bank-kyc', 'kyc:verified'],
  ]);
  const g = Mapping.fromPairs(disclosed, proof, [
    ['age:24', '18+'],
    ['student:true', 'enrolled'],
    ['kyc:verified', 'verified'],
  ]);

  it('reports preserved properties for a 1:1 pipeline', () => {
    const a = analyzeComposition(f, g);
    expect(a.f.bijective).toBe(true);
    expect(a.h.bijective).toBe(true);
    expect(a.injectivityPreserved).toBe(true);
    expect(a.informationReduced).toBe(false);
    expect(a.reducedAt).toBeNull();
  });

  it('detects intended information reduction (age:24 and age:17 both -> 18+)', () => {
    const claims = new Set(['age:24', 'age:17']);
    const fAges = Mapping.fromPairs(claims, proof, [
      ['age:24', '18+'],
      ['age:17', '18+'],
    ]);
    const gIds = Mapping.fromFunction(proof, new Set(['ok']), () => 'ok');
    const a = analyzeComposition(fAges, gIds);
    expect(a.informationReduced).toBe(true);
    expect(a.reducedAt).toBe('f');
    expect(a.firstInjectivityCounterexample?.image).toBe('ok');
  });
});

describe('analyzeComposition (reduction in the second step)', () => {
  it('reports reducedAt = g when f is injective but g collapses', () => {
    const claims = new Set(['age:24', 'age:31']);
    const ages = new Set([24, 31]);
    const fAge = Mapping.fromPairs(claims, ages, [
      ['age:24', 24],
      ['age:31', 31],
    ]);
    const gOver18 = Mapping.fromFunction(ages, new Set(['18+']), () => '18+');
    const a = analyzeComposition(fAge, gOver18);
    expect(a.f.injective).toBe(true);
    expect(a.informationReduced).toBe(true);
    expect(a.reducedAt).toBe('g');
  });
});

describe('verifyBijectionPair (encode/decode round-trip guard)', () => {
  it('accepts a true bijection pair', () => {
    const encode = Mapping.fromPairs(new Set(['a', 'b']), new Set([1, 2]), [
      ['a', 1],
      ['b', 2],
    ]);
    const decode = Mapping.fromPairs(new Set([1, 2]), new Set(['a', 'b']), [
      [1, 'a'],
      [2, 'b'],
    ]);
    expect(verifyBijectionPair(encode, decode).ok).toBe(true);
  });

  it('rejects a broken decode with concrete failures (fail-closed)', () => {
    const encode = Mapping.fromPairs(new Set(['a', 'b']), new Set([1, 2]), [
      ['a', 1],
      ['b', 2],
    ]);
    const broken = Mapping.fromPairs(new Set([1, 2]), new Set(['a', 'b']), [
      [1, 'a'],
      [2, 'a'],
    ]);
    const result = verifyBijectionPair(encode, broken);
    expect(result.ok).toBe(false);
    expect(result.failures.length).toBeGreaterThan(0);
  });
});

describe('verifyTrustEquivalence (trust propagation must be transitive)', () => {
  const creds = new Set(['credA', 'credB', 'credC']);

  it('accepts a real equivalence relation', () => {
    const levels: Record<string, string> = { credA: 'high', credB: 'high', credC: 'low' };
    expect(verifyTrustEquivalence(creds, (a, b) => levels[a] === levels[b]).ok).toBe(true);
  });

  it('rejects a non-transitive trust relation', () => {
    // credA~credB, credB~credC, but NOT credA~credC: propagation breaks.
    const r = verifyTrustEquivalence(
      creds,
      (a, b) =>
        (a === 'credA' && b === 'credB') ||
        (a === 'credB' && b === 'credA') ||
        (a === 'credB' && b === 'credC') ||
        (a === 'credC' && b === 'credB') ||
        a === b
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('transitive');
  });
});
