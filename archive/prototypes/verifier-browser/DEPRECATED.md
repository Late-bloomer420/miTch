# DEPRECATED — verifier-browser (archived 2026-06-11)

**Status:** Archived prototype. NOT part of the active workspace, build, or test
matrix. Do not import from the active tree (`src/**`) — CI enforces this via
`pnpm guard:archived-imports`.

## Why archived
`BrowserVerifier` was a proof-of-concept that **skipped real signature
verification** and returned a hard-coded success (`mockResponse … success:true`).
Shipping or importing it from an active path would silently turn the verifier
into a no-op — a CRITICAL security-narrative liability that undermines the
trust-kit security sign-off.

## What to use instead
Real verification lives in:
- `@askmi/verifier-sdk` (transport + proof-boundary, ajv claim-request validation)
- `@askmi/predicates` (`verifyPredicateResult`, canonical `buildAgeOver18Predicate`)
- `src/apps/verifier-demo/backend` (the live `/present` age-verification path)

## If you need a browser-side verifier later
Build it fresh against `@askmi/verifier-sdk` with genuine signature checks; do
not revive this stub. Tracked under EPIC G-100.6 (see `docs/BACKLOG.md`).
