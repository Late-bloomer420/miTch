# discrete-core review — 2026-10-23

- **Scope:** `@askmi/discrete-core` on branch `feat/discrete-core` (draft PR #189), diff `master...feat/discrete-core`
- **Source revision:** `a4f7fca` (master base `a21ac24`)
- **Method:** read-only code review + throwaway edge-case/scaling probe (sources run via `tsx` outside the repo). The package's own Vitest suite was **not** re-run for this review; the 32/32 claim in `STATE.md` is the branch author's observation.
- **Recheck:** at `a11dfdb` F-1, F-2, F-3 remain open; F-4 resolved by `95f1fe3` (SameValueZero equality + presence checks).
- **Recheck 2:** F-1, F-2, F-3 resolved by `beeae79`; verified at `beeae79` on 2026-10-23 (Node 22.22.0, pnpm 9.15.9, Linux cloud container): package 40/40 tests, `pnpm build` ok, `pnpm test` 47/47 turbo tasks, `pnpm lint` 12/12 tasks (0 errors; 7 pre-existing `wallet-pwa` warnings). F-1 probe re-run (`sameLevel = () => true`): n=20 2 ms, n=40 7 ms, n=80 10 ms (before: 25 / 378 / 12 423 ms on the same machine). F-5: typo fixed; `TrustLevel`, file name and the trust-model wording remain open.
- **Status:** F-1–F-4 resolved; F-5 and the product-scope wording remain open — tracked as DC-04 in `docs/BACKLOG.md`. This document closes no gate.

## Findings (most severe first)

### F-1 `verifyTrustEquivalence` scales ~n⁵–n⁶ — ✅ resolved in `beeae79`

`Relation.holds()` is a linear scan over the pair list; `isTransitive()` nests a loop over all pairs with `holds()` inside. With n elements there are up to n² pairs.

Observed (`sameLevel = () => true`):

| n   | time      |
| --- | --------- |
| 20  | 42 ms     |
| 40  | 891 ms    |
| 80  | 26 760 ms |

**Fix:** index pairs once as `Map<A, Set<B>>` in `Relation`; `holds()` becomes O(1).

### F-2 `Relation.equivalenceClasses()` is not fail-closed — ✅ resolved in `beeae79`

On a non-equivalence it silently returns a partition. Example: `new Relation([[1, 2]]).equivalenceClasses(new Set([1, 2, 3]))` → `{1}, {2}, {3}` although 1 R 2.

**Fix:** guard with `isEquivalenceOn(M)` and throw otherwise.

### F-3 Test fixture models a minor proving "18+" — ✅ resolved in `beeae79`

`tests/mitc-applications.test.ts` uses `['age:17', '18+']` as an intended reduction. Mathematically irrelevant to the assertion, but it is the exact failure the ADOPT-1 age/liquor-store profile must prevent. Use e.g. `age:24`/`age:31` → `18+`.

### F-4 Documented SameValueZero comparison not honoured — ✅ resolved in `95f1fe3`

The README and module docs claim SameValueZero; checks use `===`:

- `Mapping.fromPairs` with a repeated `NaN` image throws `not-well-defined`
- `new Relation([[NaN, NaN]]).isReflexiveOn(new Set([NaN]))` → `false`
- `apply()` treats an `undefined` image as "not in domain" (`get() === undefined` instead of `has()`), throwing `argument-not-in-domain`

**Fix:** use `Object.is`-with-zero semantics / `Map.has`, or correct the docs to "`===` identity".

### F-5 Minor

- `TrustLevel` is exported but unused
- typo "EQUIVALENENCE" in a doc comment
- file name `mitc-applications.ts` (presumably `mitch-…`)
- `verifyTrustEquivalence` is tautological when `sameLevel` derives from a level function

## Fit with product scope

- **Trust model:** the comment "propagated issuer trust must be transitive" contradicts the ADOPT-0b model, where verifiers trust issuers explicitly via the trust list, not by propagation. Reword or invert.
- **Selective disclosure:** `analyzeComposition` is a teaching analogy; real SD is SD-JWT disclosures and predicate proofs, and no product path can feed it today.
- **Product value:** `findDuplicateKeys` (credential-ID uniqueness) is the one guard with a direct product use case. Any wiring is a separate, bounded task.
- **Priority:** does not advance ADOPT-1 or #170–#173 / EV-05. Correctly tracked as P2 and "not wired".

## Recommendation

1. Fix F-1 to F-3 before merging PR #189 (F-4 already resolved).
2. Reframe the README and comments as "lecture concepts with miTch analogies" rather than product requirements.
3. Optional follow-up: wire `findDuplicateKeys` into wallet credential storage as its own task.
