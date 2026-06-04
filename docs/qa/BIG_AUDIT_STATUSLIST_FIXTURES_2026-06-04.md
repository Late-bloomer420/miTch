# Big Audit Slice — StatusList Test Fixtures (S2-05)

**Date:** 2026-06-04
**Scope:** Sprint 02 slice S2-05 — trust-/status-list test fixtures as a reusable helper
**Branch:** `chore/s2-05-statuslist-test-helpers` (off `chore/full-askmi-rebrand`)

## What Changed

- Added `src/packages/revocation-statuslist/src/test-helpers.ts` exporting pure
  fixture builders: `makeStatusListEntry`, `makeStatusListCredential`,
  `TEST_STATUS_LIST_URL`, `TEST_STATUS_LIST_ISSUER`.
- Exposed it via a package `exports` subpath `@askmi/revocation-statuslist/test-helpers`.
- Refactored the duplicated builders out of three test surfaces:
  - `revocation-statuslist` `checker.test.ts` (in-package, relative import)
  - `revocation-statuslist` `multi-source.test.ts` (in-package, thin adapter for
    its reversed `(url, index)` convention)
  - `@askmi/integration-tests` `fail-closed-golden.test.ts` (cross-package, subpath import)
- Fixed a pre-existing coupling anti-pattern exposed by the `exports` map:
  `shared-crypto` deep-imported `@askmi/revocation-statuslist/src/types`; it now
  imports the same (already re-exported) types from the package root.

## Audit Findings

### Duplication, Fixed

- `makeStatusListEntry` was copy/pasted in three test files and had already
  drifted in **signature**: `(index, url)` in two surfaces vs reversed
  `(url, index)` in `multi-source`. A shared options-friendly builder removes the
  copy/paste; the reversed surface keeps a one-line adapter rather than rewriting
  every call site.
- `makeStatusListCredential` / `makeCredential` credential shells were duplicated
  between `integration-tests` and `checker.test`. The shared builder takes an
  already-encoded `encodedList` string, so each caller keeps its own bitstring
  encoding and **no revocation/encoding behavior changes**.

### Coupling, Fixed

- `@askmi/revocation-statuslist/src/types` deep imports in `shared-crypto` reached
  into package source and would break once the package is published. The package
  already re-exports those types from its index (`export * from './types'`), so
  the imports now use the package root.

### Deferred

- Trust-list (LOTL/TSL) test fixtures were left untouched in this slice; the
  status-list builders already satisfy the "second runtime test surface reuses the
  same builders" acceptance criterion. A follow-up could extend the helper module
  with trust-list builders if a second trust-list test surface appears.

## Verification

- `pnpm build` — pass, 30/30 Turbo tasks
- `pnpm test` — pass, 45/45 Turbo tasks (revocation-statuslist 26, integration-tests 54)
- `pnpm lint` — pass, 10/10 Turbo tasks
- `pnpm guard:rebrand` — pass
