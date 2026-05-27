# Privacy Audit Checklist

Use this checklist for code review, architecture review, and policy validation.

## Boundary

- Identify all user data, claims, credentials, keys, DIDs, nonces, verifier identifiers, policy identifiers, and audit artifacts.
- Mark whether each item is raw data, derived data, proof, metadata, or cryptographic material.
- Confirm the owner package and actor boundary.

## Data Minimization

- Prefer predicates such as age-over or set-membership over raw attribute disclosure.
- Reject broad claim sets where a narrower proof would satisfy the purpose.
- Check that UI copy does not imply wider sharing than the protocol performs.

## Storage And Retention

- Raw PII must not be written to logs, telemetry, local storage, IndexedDB, evidence packs, or server caches unless explicitly justified.
- Encrypted storage must fail closed on wrong keys or corrupt payloads.
- Ephemeral values must have clear disposal, TTL, or one-time-use semantics.

## Policy Engine

- Missing policy, unknown version, unknown verifier, and unresolved conflicts must DENY.
- ALLOW requires evidence: matched rule, reason, active policy hash, and auditable decision metadata.
- DENY and PROMPT paths must not accidentally produce presentation material.

## DecisionCapsule

- Required fields: `verdict`, `decision_id`, `policy_hash`.
- `policy_hash` binds to the full active PolicyManifest.
- `rule_hash` may be useful for audit/debugging but must not replace `policy_hash`.

## Crypto And Binding

- Verify nonce, audience, challenge, origin/RP ID, and expiration binding.
- DID resolution and revocation lookup failures must not silently allow.
- Pairwise DIDs and unlinkability controls should be preferred over stable identifiers.

## Tests

- Add or run negative tests for malformed input, missing policy, unknown actor, resolver failure, revoked credential, replay, expired request, and wrong cryptographic binding.
- For narrow changes, run the package test. For shared behavior, run affected packages plus integration fail-closed tests.
