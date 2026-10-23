/**
 * Relations as subsets of cartesian products (MCI Computational Thinking,
 * Mengen & Abbildungen, Hartmann Kap. 1.2 — Definition 1.7 ff.).
 *
 * A relation R on M x N is fully described by the set of pairs (x, y)
 * for which the relation holds. All checks here operate on FINITE,
 * explicitly enumerated relations; elements are compared with
 * SameValueZero/identity, so use primitives or stable references.
 */

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

  constructor(pairs: Iterable<RelationPair<A, B>>) {
    this.pairList = Array.from(pairs);
  }

  /** All pairs, in insertion order. */
  pairs(): readonly RelationPair<A, B>[] {
    return this.pairList;
  }

  /** Whether (x, y) in R. */
  holds(x: A, y: B): boolean {
    return this.pairList.some(([a, b]) => a === x && b === y);
  }

  /** Reflexivity on M: for all x in M, xRx. (Definition 1.8) */
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
    return this.pairList.every(([a, b]) => a === b || !self.holds(b, a));
  }

  /** Transitivity: xRy and yRz imply xRz. */
  isTransitive(): boolean {
    const self = this as unknown as Relation<unknown, unknown>;
    for (const [a, b] of this.pairList) {
      for (const [b2, c] of this.pairList) {
        if (b === b2 && !self.holds(a, c)) return false;
      }
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
   */
  equivalenceClasses(M: ReadonlySet<A & B>): Map<A & B, ReadonlySet<A & B>> {
    const self = this as unknown as Relation<unknown, unknown>;
    const classes = new Map<A & B, Set<A & B>>();
    for (const x of M) {
      let rep: A & B | undefined = undefined;
      for (const [r, set] of classes) {
        if (set.has(x) || self.holds(x, r)) {
          rep = r as A & B;
          break;
        }
      }
      if (rep === undefined) {
        rep = x;
        classes.set(rep, new Set());
      }
      classes.get(rep)!.add(x);
    }
    return classes;
  }
}
