/**
 * Mappings (Abbildungen), their properties, composition and inverse
 * (MCI Computational Thinking, Hartmann Definition 1.13, 1.15, 1.16, 1.18).
 *
 * Core rule: EVERY element of the definition set has EXACTLY ONE image
 * ("genau ein Bild" — the most important word of the definition).
 * All constructors are fail-closed: they throw instead of silently
 * accepting a not-well-defined assignment.
 *
 * Sets are finite and explicitly enumerated; elements are compared with
 * SameValueZero/identity.
 */

/** Domain-codomain mismatch kinds thrown by this module. */
export type MappingErrorCode =
  | 'not-well-defined'
  | 'image-not-in-codomain'
  | 'argument-not-in-domain'
  | 'incompatible-composition'
  | 'not-bijective';

/** Error with a machine-readable `code` for fail-closed handling. */
export class MappingError extends Error {
  readonly code: MappingErrorCode;
  constructor(code: MappingErrorCode, message: string) {
    super(message);
    this.name = 'MappingError';
    this.code = code;
  }
}

/**
 * A mapping f: M -> N.
 *
 * Construct via {@link Mapping.fromPairs} (Wertetabelle) or
 * {@link Mapping.fromFunction} (Zuordnungsvorschrift).
 */
export class Mapping<M, N> {
  private readonly table: ReadonlyMap<M, N>;

  private constructor(
    readonly domain: ReadonlySet<M>,
    readonly codomain: ReadonlySet<N>,
    table: ReadonlyMap<M, N>,
  ) {
    this.table = table;
  }

  /**
   * Build a mapping from an explicit value table.
   * Fail-closed: throws if an element of the domain has no image, has two
   * different images, or an image lies outside the codomain.
   */
  static fromPairs<M, N>(
    domain: ReadonlySet<M>,
    codomain: ReadonlySet<N>,
    pairs: Iterable<readonly [M, N]>,
  ): Mapping<M, N> {
    const table = new Map<M, N>();
    for (const [x, y] of pairs) {
      if (!domain.has(x)) {
        throw new MappingError('not-well-defined', `argument ${safe(x)} is not an element of the definition set`);
      }
      if (!codomain.has(y)) {
        throw new MappingError('image-not-in-codomain', `image ${safe(y)} of ${safe(x)} is not an element of the target set`);
      }
      const prev = table.get(x);
      if (prev !== undefined && prev !== y) {
        throw new MappingError('not-well-defined', `${safe(x)} has two different images (${safe(prev)}, ${safe(y)})`);
      }
      table.set(x, y);
    }
    if (table.size !== domain.size) {
      throw new MappingError('not-well-defined', 'some element of the definition set has no image');
    }
    return new Mapping(domain, codomain, table);
  }

  /** Build a mapping by evaluating f over the (finite) definition set. */
  static fromFunction<M, N>(
    domain: ReadonlySet<M>,
    codomain: ReadonlySet<N>,
    f: (x: M) => N,
  ): Mapping<M, N> {
    const pairs: [M, N][] = [];
    for (const x of domain) pairs.push([x, f(x)]);
    return Mapping.fromPairs(domain, codomain, pairs);
  }

  /** f(x). Fail-closed: throws if x is outside the definition set. */
  apply(x: M): N {
    const y = this.table.get(x);
    if (y === undefined) {
      throw new MappingError('argument-not-in-domain', `argument ${safe(x)} is outside the definition set`);
    }
    return y;
  }

  /** The image set f(M) subset N. */
  image(): Set<N> {
    return new Set(this.table.values());
  }

  /** The value table as [x, f(x)] pairs. */
  entries(): [M, N][] {
    return Array.from(this.table.entries());
  }

  /**
   * Injective (Definition 1.16): different arguments have different
   * images — "kein Bild doppelt vergeben".
   */
  isInjective(): boolean {
    return new Set(this.table.values()).size === this.table.size;
  }

  /**
   * Surjective: every element of the target set has at least one preimage
   * — "kein Element der Zielmenge bleibt unbenutzt".
   */
  isSurjective(): boolean {
    const img = this.image();
    for (const y of this.codomain) if (!img.has(y)) return false;
    return true;
  }

  /** Bijective: injective and surjective (1:1 correspondence). */
  isBijective(): boolean {
    return this.isInjective() && this.isSurjective();
  }

  /**
   * A single counterexample (Gegenbeispiel) against injectivity, or null.
   * Per the lecture: disproving a property only takes ONE witness.
   */
  injectivityViolation(): { x1: M; x2: M; image: N } | null {
    const seen = new Map<N, M>();
    for (const [x, y] of this.table) {
      const prev = seen.get(y);
      if (prev !== undefined) return { x1: prev, x2: x, image: y };
      seen.set(y, x);
    }
    return null;
  }

  /** A single element of the target set without preimage, or null. */
  surjectivityViolation(): N | null {
    const img = this.image();
    for (const y of this.codomain) if (!img.has(y)) return y;
    return null;
  }
}

/**
 * Composition g after f (Hintereinanderausführung, Definition 1.15):
 * (g o f)(x) = g(f(x)).
 *
 * Fail-closed on interface compatibility: requires image(f) subset
 * domain(g) — otherwise the composition is not defined.
 */
export function compose<M, N, S>(f: Mapping<M, N>, g: Mapping<N, S>): Mapping<M, S> {
  for (const y of f.image()) {
    if (!g.domain.has(y)) {
      throw new MappingError('incompatible-composition', `image ${safe(y)} of f is outside the definition set of g`);
    }
  }
  return Mapping.fromFunction(f.domain, g.codomain, (x) => g.apply(f.apply(x)));
}

/**
 * Inverse mapping f^-1 (Definition 1.18). Exists IFF f is bijective;
 * throws otherwise ("Nur bijektive Abbildungen besitzen eine
 * Umkehrabbildung").
 */
export function inverse<M, N>(f: Mapping<M, N>): Mapping<N, M> {
  if (!f.isBijective()) {
    throw new MappingError('not-bijective', 'f is not bijective; no inverse mapping exists');
  }
  return Mapping.fromPairs(f.codomain, f.domain, f.entries().map(([x, y]) => [y, x] as [N, M]));
}

/**
 * Cardinality comparison (Definition 1.20): two finite sets are equally
 * powerful ("gleichmaechtig") iff a bijection between them exists.
 * Returns a witness bijection, or null if the sizes differ.
 */
export function bijectionWitness<M, N>(a: ReadonlySet<M>, b: ReadonlySet<N>): Mapping<M, N> | null {
  if (a.size !== b.size) return null;
  const ai = Array.from(a);
  const bi = Array.from(b);
  return Mapping.fromPairs(a, b, ai.map((x, i) => [x, bi[i]] as [M, N]));
}

function safe(v: unknown): string {
  try {
    return typeof v === 'string' ? v : JSON.stringify(v);
  } catch {
    return String(v);
  }
}
