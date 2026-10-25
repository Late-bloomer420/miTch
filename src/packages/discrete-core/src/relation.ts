/**
 * Relations as subsets of cartesian products (MCI Computational Thinking,
 * Mengen & Abbildungen, Hartmann Kap. 1.2 — Definition 1.7 ff.).
 *
 * A relation R on M x N is fully described by the set of pairs (x, y)
 * for which the relation holds. All checks here operate on FINITE,
 * explicitly enumerated relations; elements are compared with
 * SameValueZero/identity, so use primitives or stable references.
 */

import { sameValueZero } from './equality.js';

/** A single pair of a relation. */
export type RelationPair<A, B> = readonly [A, B];

/**
 * A finite relation R subset M x N.
 *
 * For the properties defined on a single set (reflexive, symmetric,
 * antisymmetric, transitive, equivalence, order) M and N are the same
 * set; pass that set via the `on` parameter.
 */
export class Relation<A, B = A> {
  private readonly pairList: readonly RelationPair<A, B>[];
  /** x -> { y | xRy }. Map/Set use SameValueZero, so lookups match `sameValueZero`. */
  private readonly successors: ReadonlyMap<A, ReadonlySet<B>>;

  constructor(pairs: Iterable<RelationPair<A, B>>) {
    this.pairList = Array.from(pairs, ([a, b]) => [a, b] as const);
    const index = new Map<A, Set<B>>();
    for (const [a, b] of this.pairList) {
      let set = index.get(a);
      if (set === undefined) {
        set = new Set();
        index.set(a, set);
      }
      set.add(b);
    }
    this.successors = index;
  }

  /** Detached pairs, in insertion order; neither the list nor tuples expose internal state. */
  pairs(): readonly RelationPair<A, B>[] {
    return this.pairList.map(([a, b]) => [a, b] as const);
  }

  /** Whether (x, y) in R. O(1) via the successor index. */
  holds(x: A, y: B): boolean {
    return this.successors.get(x)?.has(y) ?? false;
  }

  /**
   * Reflexivity on M: for all x in M, xRx. (Definition 1.8)
   *
   * Only meaningful for a relation on one set (M = N). The `A & B` parameter
   * type is a typing workaround so M can be passed for both components; it
   * does not make the check meaningful for relations between two different
   * sets. The same applies to `isEquivalenceOn`, `isOrderOn` and
   * `equivalenceClasses`.
   */
  isReflexiveOn(M: ReadonlySet<A & B>): boolean {
    for (const x of M) if (!this.holds(x, x)) return false;
    return true;
  }

  /** Symmetry: xRy implies yRx. */
  isSymmetric(): boolean {
    const self = this as unknown as Relation<A, A>;
    return this.pairList.every(([a, b]) => (self as Relation<unknown, unknown>).holds(b, a));
  }

  /** Antisymmetry: aRb and bRa imply a = b (order relations). */
  isAntisymmetric(): boolean {
    const self = this as unknown as Relation<unknown, unknown>;
    return this.pairList.every(([a, b]) => sameValueZero(a, b) || !self.holds(b, a));
  }

  /**
   * Transitivity: xRy and yRz imply xRz.
   * For each pair (a, b), every successor of b must be a successor of a.
   */
  isTransitive(): boolean {
    const index = this.successors as unknown as ReadonlyMap<unknown, ReadonlySet<unknown>>;
    for (const [a, b] of this.pairList) {
      const fromB = index.get(b);
      if (fromB === undefined) continue;
      const fromA = index.get(a) as ReadonlySet<unknown>;
      for (const c of fromB) if (!fromA.has(c)) return false;
    }
    return true;
  }

  /**
   * Equivalence relation on M (Definition 1.9):
   * reflexive + symmetric + transitive.
   */
  isEquivalenceOn(M: ReadonlySet<A & B>): boolean {
    return this.isReflexiveOn(M) && this.isSymmetric() && this.isTransitive();
  }

  /**
   * Order relation on M (Definition 4.1):
   * reflexive + antisymmetric + transitive.
   */
  isOrderOn(M: ReadonlySet<A & B>): boolean {
    return this.isReflexiveOn(M) && this.isAntisymmetric() && this.isTransitive();
  }

  /**
   * Equivalence classes of an equivalence relation on M: the induced
   * partition ("Welche Objekte gehoeren zusammen?").
   * The representative of each class is its first-discovered element.
   *
   * Fail-closed: throws if R is not an equivalence relation on M, instead of
   * returning a partition that does not reflect R.
   */
  equivalenceClasses(M: ReadonlySet<A & B>): Map<A & B, ReadonlySet<A & B>> {
    if (!this.isEquivalenceOn(M)) {
      throw new Error('relation is not an equivalence relation on M; no partition exists');
    }
    const self = this as unknown as Relation<unknown, unknown>;
    const classes = new Map<A & B, Set<A & B>>();
    for (const x of M) {
      let target: Set<A & B> | null = null;
      for (const [r, set] of classes) {
        if (set.has(x) || self.holds(x, r)) {
          target = set;
          break;
        }
      }
      if (target === null) {
        target = new Set();
        classes.set(x, target);
      }
      target.add(x);
    }
    return classes;
  }
}
