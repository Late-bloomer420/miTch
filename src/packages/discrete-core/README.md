# @askmi/discrete-core

Discrete-math primitives from the MCI "Computational Thinking" lecture
(Mengen & Abbildungen, Hartmann Kap. 1.2–1.3) as a small library with
zero runtime dependencies (TypeScript and Vitest are dev-only),
fail-closed by design — with miTch analogies.

## Scope

This package teaches lecture concepts with miTch/AskMI analogies. It is not a
product requirement and is not wired into the wallet, verifier or policy
engine; any wiring is a separate, bounded task. Real selective disclosure in
AskMI is SD-JWT disclosures and predicate proofs, not `analyzeComposition`.

| Lecture concept                                 | miTch/AskMI analogy                                                                                            |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Mapping ("every element has EXACTLY ONE image") | credential → credential-ID, user → wallet key, session → token                                                 |
| Injectivity                                     | unique keys: no two credentials may share an ID                                                                |
| Surjectivity                                    | completeness: all enum values / classification targets actually occur                                          |
| Bijection                                       | encryption/decryption, encode/decode — verlustfreie Hin- und Rueckuebersetzung                                 |
| Composition                                     | selective-disclosure pipeline (credential → disclosed claims → proof); injectivity may be _intentionally_ lost |
| Inverse mapping                                 | only exists for bijections — inverse() throws otherwise                                                        |
| Equivalence relations                           | credential classifications, e.g. assurance-level groups (not issuer trust)                                     |
| Order relations                                 | priorities, versions, expiry sorting                                                                           |
| Cardinality / bijection witness                 | loss-free 1:1 mapping between data sets (record ↔ primary key)                                                 |
| Gegenbeispiel                                   | one counterexample disproves a property — used for fast fail-closed tests                                      |

All sets are finite and explicitly enumerated; elements are compared with
SameValueZero/identity.

## API

### Relation (from `./relation.js`)

```ts
const M = new Set([2, 3, 5]);
const lessThan = new Relation<number>([
  [3, 2],
  [5, 2],
  [5, 3],
]);
lessThan.isTransitive(); // true
lessThan.isReflexiveOn(M); // false
const sameHair = new Relation<string>([
  ['Anna', 'Anna'],
  ['Anna', 'Ben'],
  ['Ben', 'Anna'],
  ['Ben', 'Ben'],
  ['Clara', 'Clara'],
]);
sameHair.isEquivalenceOn(new Set(['Anna', 'Ben', 'Clara'])); // true
sameHair.equivalenceClasses(new Set(['Anna', 'Ben', 'Clara'])); // partition
```

### Mapping (from `./mapping.js`)

```ts
const f = Mapping.fromPairs(students, matriculation, [['Anna', 241001], ...]);
f.apply('Anna');          // 241001
f.isInjective();          // true
f.injectivityViolation(); // first counterexample or null

const g = Mapping.fromFunction(points, grades, (p) => (p >= 90 ? 1 : ...));
const h = compose(f, g);  // throws MappingError('incompatible-composition') if image(f) ⊄ domain(g)
inverse(f);               // throws MappingError('not-bijective') unless f is bijective
bijectionWitness(A, B);   // bijection between equally sized sets, or null
```

Fail-closed errors carry machine-readable codes: `not-well-defined`,
`image-not-in-codomain`, `argument-not-in-domain`,
`incompatible-composition`, `not-bijective`.

### miTch application guards (from `./mitch-applications.js`)

```ts
// Injectivity guard for credential IDs (one counterexample suffices)
findDuplicateKeys(credentials, (c) => c.id); // DuplicateKeyFinding | null

// Selective-disclosure pipeline analysis
analyzeComposition(f, g); // f/g/h properties, injectivityPreserved, informationReduced, reducedAt

// Encode/decode bijection verification (both round-trip identities)
verifyBijectionPair(encode, decode); // { ok, failures }

// A classification predicate must be an equivalence relation.
// Not issuer trust: AskMI verifiers trust issuers explicitly via the trust list.
verifyTrustEquivalence(credentials, sameLevel); // { ok, reason }
```

## Tests

`pnpm --filter @askmi/discrete-core test` — all examples mirror the lecture
(<, <=, =, !=; Matrikelnummern; Punkte → Note; x²; Mächtigkeit) plus
miTch guards.

## Limitations

- Finite, enumerable sets only (no infinite-domain proofs).
- Identity/SameValueZero element comparison — use primitives or stable references.
- Pure logic: no crypto, no storage, no network. Compose it into wallet/
  verifier code; it never bypasses the policy engine.
