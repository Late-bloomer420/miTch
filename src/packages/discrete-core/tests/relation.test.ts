import { describe, expect, it } from 'vitest';
import { Relation } from '../src/index.js';

const M = new Set([2, 3, 5]);

const allPairs = (): [number, number][] => {
  const pairs: [number, number][] = [];
  for (const a of M) for (const b of M) pairs.push([a, b]);
  return pairs;
};

const lessThan = new Relation<number>([[3, 2], [5, 2], [5, 3]]);
const leq = new Relation<number>(allPairs().filter(([a, b]) => a <= b));
const equal = new Relation<number>(allPairs().filter(([a, b]) => a === b));
const notEqual = new Relation<number>(allPairs().filter(([a, b]) => a !== b));

describe('Relation properties (lecture examples: <, <=, =, !=)', () => {
  it('< is transitive, not reflexive, not symmetric', () => {
    expect(lessThan.isTransitive()).toBe(true);
    expect(lessThan.isReflexiveOn(M)).toBe(false);
    expect(lessThan.isSymmetric()).toBe(false);
  });

  it('<= is reflexive and transitive, not symmetric (an order)', () => {
    expect(leq.isReflexiveOn(M)).toBe(true);
    expect(leq.isTransitive()).toBe(true);
    expect(leq.isSymmetric()).toBe(false);
    expect(leq.isOrderOn(M)).toBe(true);
  });

  it('= is an equivalence relation', () => {
    expect(equal.isEquivalenceOn(M)).toBe(true);
  });

  it('!= is symmetric, not reflexive, not transitive', () => {
    expect(notEqual.isSymmetric()).toBe(true);
    expect(notEqual.isReflexiveOn(M)).toBe(false);
    expect(notEqual.isTransitive()).toBe(false);
  });
});

describe('Equivalence classes ("hat gleiche Haarfarbe wie")', () => {
  it('partitions the set into classes', () => {
    const people = new Set(['Anna', 'Ben', 'Clara']);
    // Anna and Ben share hair colour; Clara does not.
    const sameHair = new Relation<string>([
      ['Anna', 'Anna'], ['Anna', 'Ben'], ['Ben', 'Anna'], ['Ben', 'Ben'], ['Clara', 'Clara'],
    ]);
    expect(sameHair.isEquivalenceOn(people)).toBe(true);
    const classes = Array.from(sameHair.equivalenceClasses(people).values()).map((s) => s.size);
    expect(classes.sort()).toEqual([1, 2]);
  });
});
