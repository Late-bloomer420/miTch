# Policy Engine Spec (Phase 0)

## Artifacts
- **Policy Manifest**: canonical description of:
  - supported predicates
  - required bindings
  - deny rules
  - gate precedence
- **AQDR (Audit Query / Decision Receipt) Mock**
  - record of: request hash, decision, reason codes, timestamps, verifier signature (no raw PII)
- **AAD (Associated Auth Data)**
  - binds decisions/proofs to context; prevents swapping/replay
- **WORM logging**
  - append-only receipts for audit and non-repudiation
- **Rate Limiting**
  - protect verification API (Phase 0: fixed window per requester)

## Gate precedence (must be enforced)
1. Rate limit (cheap, early)
2. Schema validation (fail closed)
3. Binding validation (request hash / nonce / audience / expiry)
4. Policy evaluation (least disclosure / purpose limitation)
5. Crypto verification (expensive)
6. Receipt logging (WORM)

## Error handling
- Any missing field, unknown predicate, or ambiguous match => **DENY**
- Deny must be explicit + machine-readable reason codes.

## Logging policy
- Logs must not contain raw PII.
- Avoid stable identifiers.
- Prefer coarse-grained operational metrics (counts, buckets) over per-user traces.

## Testing requirements
- “Honesty Check”: zero matches for enclave/TEE claims if not implemented.
- Regression tests:
  - fail closed on missing path
  - binding.requestHash matches actual hash
  - sign/verify roundtrip for key guardian
  - gate precedence tests
