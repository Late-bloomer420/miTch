# miTch API And Interface Patterns

## Defaults

- Prefer proofs over values.
- Prefer predicates over raw claims.
- Prefer explicit `Result`-style failure modes for security and policy decisions.
- Validate all external input at the boundary.
- Bind protocol artifacts to nonce/challenge, audience, issuer/verifier identity, timestamp, and policy where applicable.

## TypeScript

- Put shared contracts in `src/packages/shared-types` when multiple packages depend on them.
- Use package-local types when the type is implementation detail.
- Use Zod schemas for runtime validation of external inputs.
- Avoid `any`; if unavoidable, isolate it at an adapter boundary and convert to a typed value immediately.

## Naming

- Predicates: `is...`, `has...`, `can...`, `verify...`.
- Actions: `issue...`, `present...`, `revoke...`, `evaluate...`, `resolve...`.
- Events: `...Received`, `...Evaluated`, `...Revoked`, `...Anchored`.
- Policy artifacts should keep established names: `PolicyManifest`, `DecisionCapsule`, `policy_hash`.

## Failure Behavior

- Policy and security decisions must not throw through to a caller that might treat failure as success.
- Missing, malformed, unknown, expired, revoked, or unverifiable state must DENY or return a hard failure.
- UI and demo layers must not mask DENY as a successful presentation.
