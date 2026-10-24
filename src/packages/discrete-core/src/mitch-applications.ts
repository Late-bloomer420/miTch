/**
 * Lecture concepts applied to miTch/AskMI-style data, as fail-closed helpers.
 *
 * These are analogies and reusable checks, not product requirements: none of
 * them is wired into the wallet, verifier or policy engine.
 *
 * - injective keying  -> credential IDs, wallet keys (UUID-style)
 * - composition       -> selective-disclosure pipeline step analysis
 * - bijection         -> encode/decode (crypto) round-trip verification
 * - Gegenbeispiel     -> one counterexample is enough to disprove
 */

import { sameValueZero } from './equality.js';
import { Mapping, MappingError, compose, inverse } from './mapping.js';
import { Relation } from './relation.js';

/** Result of a duplicate-key scan: one concrete counterexample or null. */
export interface DuplicateKeyFinding<T> {
  readonly kind: 'duplicate-key';
  readonly key: string;
  readonly offenders: readonly T[];
}

/**
 * Injectivity guard for object keys (credential IDs, wallet addresses,
 * session tokens ...). Returns the FIRST counterexample — per the
 * lecture, one duplicate is enough to disprove injectivity.
 * Returns null when the key assignment is injective.
 */
export function findDuplicateKeys<T>(
  items: readonly T[],
  keyOf: (item: T) => string
): DuplicateKeyFinding<T> | null {
  const byKey = new Map<string, T[]>();
  for (const item of items) {
    const key = keyOf(item);
    const bucket = byKey.get(key);
    if (bucket) bucket.push(item);
    else byKey.set(key, [item]);
  }
  for (const [key, offenders] of byKey) {
    if (offenders.length > 1) return { kind: 'duplicate-key', key, offenders };
  }
  return null;
}

/** Property snapshot of a mapping, for pipeline reports. */
export interface MappingProperties {
  readonly injective: boolean;
  readonly surjective: boolean;
  readonly bijective: boolean;
}

/** Analysis of a two-step pipeline f then g, with a final composition h = g o f. */
export interface CompositionAnalysis<M, S> {
  readonly f: MappingProperties;
  readonly g: MappingProperties;
  readonly h: MappingProperties;
  /** True when the whole pipeline h = g o f is injective (nothing collapses). */
  readonly injectivityPreserved: boolean;
  /**
   * Human-readable note about information reduction, mirroring the
   * lecture's didactic comment (Studierende -> Punkte -> Note):
   * injectivity is typically LOST when several inputs collapse onto
   * the same output. In miTch terms: this is where selective
   * disclosure reduces credential claims to a minimal proof —
   * decide consciously whether that reduction is intended.
   *
   * True whenever h is not injective, regardless of which step collapses.
   */
  readonly informationReduced: boolean;
  /**
   * The first step where inputs collapse: 'f' if f itself is not injective,
   * 'g' if f is injective but g o f is not, null if nothing is lost.
   */
  readonly reducedAt: 'f' | 'g' | null;
  readonly firstInjectivityCounterexample: { x1: M; x2: M; image: S } | null;
}

/**
 * Analyse a two-step pipeline (e.g. Credential -> disclosed claims -> proof)
 * and report which mapping properties survive the composition.
 */
export function analyzeComposition<M, N, S>(
  f: Mapping<M, N>,
  g: Mapping<N, S>
): CompositionAnalysis<M, S> {
  const h = compose(f, g);
  const props = (m: Mapping<unknown, unknown>): MappingProperties => ({
    injective: m.isInjective(),
    surjective: m.isSurjective(),
    bijective: m.isBijective(),
  });
  const violation = h.injectivityViolation();
  const hInjective = h.isInjective();
  const reducedAt = !f.isInjective() ? 'f' : !hInjective ? 'g' : null;
  return {
    f: props(f as unknown as Mapping<unknown, unknown>),
    g: props(g as unknown as Mapping<unknown, unknown>),
    h: props(h as unknown as Mapping<unknown, unknown>),
    injectivityPreserved: hInjective,
    informationReduced: !hInjective,
    reducedAt,
    firstInjectivityCounterexample: violation,
  };
}

/** Result of a bijection round-trip verification. */
export interface BijectionVerification {
  readonly ok: boolean;
  readonly failures: readonly string[];
}

/**
 * Bijection guard for encode/decode pairs (encryption/decryption,
 * codierung/decodierung — "verlustfreie Hin- und Rueckuebersetzung").
 *
 * Verifies BOTH identities over the finite sample sets:
 *   decode(encode(x)) = x for all x in domain(encode)
 *   encode(decode(y)) = y for all y in domain(decode)
 * Fail-closed: returns every failing witness, ok=false on any failure.
 *
 * The round-trip loops only cover the DECLARED definition sets. A pair can
 * only be a bijection if those sets match up, so set incompatibility is
 * reported as a failure even when all sampled round-trips pass:
 *   codomain(encode) subset domain(decode)
 *   codomain(decode) subset domain(encode)
 */
export function verifyBijectionPair<M, N>(
  encode: Mapping<M, N>,
  decode: Mapping<N, M>
): BijectionVerification {
  const failures: string[] = [];
  for (const y of encode.codomain) {
    if (!decode.domain.has(y)) {
      failures.push(
        `image ${String(y)} of encode is not in the definition set of decode (declared sets are incompatible)`
      );
    }
  }
  for (const x of decode.codomain) {
    if (!encode.domain.has(x)) {
      failures.push(
        `image ${String(x)} of decode is not in the definition set of encode (declared sets are incompatible)`
      );
    }
  }
  for (const x of encode.domain) {
    let decoded: M;
    try {
      decoded = decode.apply(encode.apply(x));
    } catch (e) {
      failures.push(
        `encode(${String(x)}) could not be decoded: ${e instanceof Error ? e.message : String(e)}`
      );
      continue;
    }
    if (!sameValueZero(decoded, x))
      failures.push(`decode(encode(${String(x)})) = ${String(decoded)} !== ${String(x)}`);
  }
  for (const y of decode.domain) {
    let encoded: N;
    try {
      encoded = encode.apply(decode.apply(y));
    } catch (e) {
      failures.push(
        `decode(${String(y)}) could not be re-encoded: ${e instanceof Error ? e.message : String(e)}`
      );
      continue;
    }
    if (!sameValueZero(encoded, y))
      failures.push(`encode(decode(${String(y)})) = ${String(encoded)} !== ${String(y)}`);
  }
  return { ok: failures.length === 0, failures };
}

/**
 * Verify that a "same class" predicate over a credential set is a true
 * EQUIVALENCE relation (reflexive, symmetric, transitive), i.e. that it
 * partitions the set into consistent classes (e.g. assurance-level groups).
 *
 * This is NOT a model of issuer trust. In AskMI a verifier trusts each issuer
 * explicitly via its trust list; trust is never propagated from one issuer to
 * another, so there is no transitive trust chain to verify here.
 *
 * Only useful for hand-written or ad-hoc predicates: a predicate derived from a
 * level function, `(a, b) => level(a) === level(b)`, is an equivalence by
 * construction and always passes.
 *
 * Returns { ok, reason } describing the FIRST violated property.
 */
export function verifyTrustEquivalence(
  credentials: ReadonlySet<string>,
  sameLevel: (a: string, b: string) => boolean
): { ok: boolean; reason: string | null } {
  const pairs: [string, string][] = [];
  for (const a of credentials) for (const b of credentials) if (sameLevel(a, b)) pairs.push([a, b]);
  const relation = new Relation<string>(pairs);
  if (!relation.isReflexiveOn(credentials))
    return { ok: false, reason: 'classification is not reflexive' };
  if (!relation.isSymmetric()) return { ok: false, reason: 'classification is not symmetric' };
  if (!relation.isTransitive())
    return { ok: false, reason: 'classification is not transitive (classes are inconsistent)' };
  return { ok: true, reason: null };
}

export { Mapping, MappingError, compose, inverse };
