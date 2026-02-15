# 61 — Jurisdiction Compatibility Gate v1

Stand: 2026-02-11

## Implemented
- New deny code: `DENY_JURISDICTION_INCOMPATIBLE`.
- Optional strict gate in verifier flow:
  - enabled with `REQUIRE_JURISDICTION_MATCH=1`
  - compares `RUNTIME_JURISDICTION` against request `rp.jurisdiction`
- Denies on mismatch or missing required value in strict mode.

## Purpose
Provides a fail-closed baseline for cross-jurisdiction incompatibility handling without weakening security defaults.

## Next (v2)
- Move from strict equality to policy-profile compatibility matrix.
- Add per-purpose jurisdiction rules and evidence reporting.
