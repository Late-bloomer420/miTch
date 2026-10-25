import { describe, expect, it } from 'vitest';
import { Mapping, inverse } from '../src/mapping';
import { Relation } from '../src/relation';

describe('validated mapping snapshots', () => {
  it('keeps its domain and codomain when the caller changes the input sets', () => {
    const domain = new Set([1]);
    const codomain = new Set(['a']);
    const mapping = Mapping.fromPairs(domain, codomain, [[1, 'a']]);
    domain.add(2);
    codomain.clear();
    expect([...mapping.domain]).toEqual([1]);
    expect([...mapping.codomain]).toEqual(['a']);
    expect(mapping.apply(1)).toBe('a');
    expect(() => mapping.apply(2)).toThrow();
    expect(inverse(mapping).apply('a')).toBe(1);
  });

  it('does not expose mutable internal sets through its readonly views', () => {
    const mapping = Mapping.fromPairs(new Set([1]), new Set(['a']), [[1, 'a']]);
    (mapping.domain as Set<number>).clear();
    (mapping.codomain as Set<string>).add('b');
    expect(mapping.isBijective()).toBe(true);
    expect(inverse(mapping).apply('a')).toBe(1);
  });

  it('snapshots before invoking the mapping function', () => {
    const domain = new Set([1, 2]);
    const codomain = new Set(['1', '2']);
    const mapping = Mapping.fromFunction(domain, codomain, (x) => {
      domain.clear();
      codomain.clear();
      return String(x);
    });
    expect(mapping.entries()).toEqual([
      [1, '1'],
      [2, '2'],
    ]);
    expect(mapping.isBijective()).toBe(true);
  });
});

describe('relation pair snapshots', () => {
  it('keeps the pair list and index consistent after an input tuple changes', () => {
    const pair: [number, number] = [1, 1];
    const relation = new Relation([pair]);
    pair[1] = 2;
    expect(relation.pairs()).toEqual([[1, 1]]);
    expect(relation.holds(1, 1)).toBe(true);
    expect(relation.holds(1, 2)).toBe(false);
    expect(relation.isEquivalenceOn(new Set([1]))).toBe(true);
  });

  it('does not expose its pair list or tuples to mutation', () => {
    const relation = new Relation([[1, 1]]);
    const pairs = relation.pairs() as [number, number][];
    pairs[0][1] = 2;
    pairs.push([2, 1]);
    expect(relation.pairs()).toEqual([[1, 1]]);
    expect(relation.isEquivalenceOn(new Set([1]))).toBe(true);
  });
});
