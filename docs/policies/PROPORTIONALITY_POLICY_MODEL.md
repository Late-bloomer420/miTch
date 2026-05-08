# Proportionality Policy Model (Golden Test 01)

This document describes a policy-engine decision boundary test. It is **not** a real zero-knowledge proof implementation.

## Scope

- First golden test slice for miTch policy boundary behavior.
- Purpose: `age_verification`.
- Raw claim `birthdate` is denied as disproportionate disclosure.
- Allowed path is predicate disclosure: `ageAtLeast(18)` with `PREDICATE_PROOF` response mode.

## Design constraints

- Fail-closed decision model.
- Stable explicit reason codes.
- Deterministic evaluator behavior.
- No network calls.
- Evaluator stores no raw PII and always reports `rawClaimsDisclosed: false`.
