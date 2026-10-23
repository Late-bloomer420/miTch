import { describe, expect, it } from 'vitest';
import { Mapping, MappingError, bijectionWitness, compose, inverse } from '../src/index.js';

const students = new Set(['Anna', 'Ben', 'Clara']);
const matriculation = new Set([241001, 241002, 241003]);
const grades = new Set([1, 2, 3, 4, 5]);

describe('Mapping well-definedness ("genau ein Bild")', () => {
  it('rejects an element with two images (fail-closed)', () => {
    expect(() =>
      Mapping.fromPairs(students, grades, [['Anna', 1], ['Anna', 3], ['Ben', 1], ['Clara', 3]]),
    ).toThrow(MappingError);
  });

  it('rejects an element with no image', () => {
    expect(() =>
      Mapping.fromPairs(students, grades, [['Anna', 1], ['Ben', 2]]),
    ).toThrow(MappingError);
  });

  it('rejects images outside the codomain', () => {
    expect(() =>
      Mapping.fromPairs(students, grades, [['Anna', 1], ['Ben', 2], ['Clara', 7]]),
    ).toThrow(MappingError);
  });

  it('apply throws outside the definition set (fail-closed)', () => {
    const f = Mapping.fromPairs(students, grades, [['Anna', 1], ['Ben', 2], ['Clara', 3]]);
    expect(() => f.apply('David' as never)).toThrow(MappingError);
  });
});

describe('injective / surjective / bijective (lecture examples)', () => {
  it('student -> matriculation number is bijective', () => {
    const f = Mapping.fromPairs(students, matriculation, [
      ['Anna', 241001], ['Ben', 241002], ['Clara', 241003],
    ]);
    expect(f.isInjective()).toBe(true);
    expect(f.isSurjective()).toBe(true);
    expect(f.isBijective()).toBe(true);
  });

  it('student -> grade is not injective (Anna and Ben both get 1)', () => {
    const f = Mapping.fromPairs(students, grades, [['Anna', 1], ['Ben', 1], ['Clara', 3]]);
    expect(f.isInjective()).toBe(false);
    // Gegenbeispiel: one witness is enough
    const violation = f.injectivityViolation();
    expect(violation).not.toBeNull();
    expect(violation!.image).toBe(1);
  });

  it('x -> x^2 on [-3..3] is not injective; no inverse exists', () => {
    const R = new Set([-3, -2, -1, 0, 1, 2, 3]);
    const sq = Mapping.fromFunction(R, new Set([0, 1, 4, 9]), (x) => x * x);
    expect(sq.isInjective()).toBe(false);
    expect(() => inverse(sq)).toThrow(MappingError);
  });

  it('surjectivity violation reports the unused target element', () => {
    const f = Mapping.fromPairs(students, grades, [['Anna', 1], ['Ben', 3], ['Clara', 5]]);
    expect(f.isSurjective()).toBe(false);
    expect(f.surjectivityViolation()).toBe(2);
  });
});

describe('Composition (Maxi-Aufgabe: Studierende -> Punkte -> Note)', () => {
  const points = new Set(Array.from({ length: 101 }, (_, i) => i));
  const f = Mapping.fromPairs(students, points, [['Anna', 95], ['Ben', 52], ['Clara', 85]]);
  const g = Mapping.fromFunction(points, grades, (p) =>
    p >= 90 ? 1 : p >= 80 ? 2 : p >= 70 ? 3 : p >= 60 ? 4 : 5,
  );

  it('g after f assigns each student their grade', () => {
    const h = compose(f, g);
    expect(h.apply('Anna')).toBe(1);
    expect(h.apply('Ben')).toBe(5);
    expect(h.apply('Clara')).toBe(2);
  });

  it('f is injective but not surjective; g is surjective but not injective', () => {
    expect(f.isInjective()).toBe(true);
    expect(f.isSurjective()).toBe(false);
    expect(g.isSurjective()).toBe(true);
    expect(g.isInjective()).toBe(false);
  });

  it('the composition loses injectivity (didactic point of the lecture)', () => {
    const h = compose(f, g);
    expect(h.isInjective()).toBe(false);
  });

  it('composition is fail-closed on interface compatibility', () => {
    const badG = Mapping.fromFunction(new Set([90, 95]), grades, (p) => 1);
    expect(() => compose(f, badG)).toThrow(MappingError);
  });
});

describe('Inverse mapping and cardinality', () => {
  it('inverse of a bijection round-trips to the identity', () => {
    const f = Mapping.fromPairs(students, matriculation, [
      ['Anna', 241001], ['Ben', 241002], ['Clara', 241003],
    ]);
    const inv = inverse(f);
    expect(inv.apply(f.apply('Anna'))).toBe('Anna');
    expect(f.apply(inv.apply(241003))).toBe(241003);
  });

  it('equally powerful sets have a bijection witness (Mightigkeit, Def. 1.20)', () => {
    expect(bijectionWitness(new Set(['a', 'b', 'c', 'd']), new Set([1, 2, 3, 4]))).not.toBeNull();
  });

  it('sets of different size have no bijection', () => {
    expect(bijectionWitness(new Set(['red', 'green']), new Set([1, 2, 3]))).toBeNull();
  });
});
