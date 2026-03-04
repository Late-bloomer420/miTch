# Metadata Budget v1 (Pilot)

## Normative principles

- Implementations MUST store only fields needed for security and audit outcomes.
- Implementations MUST avoid raw identifiers where a hash is sufficient.
- Implementations MUST NOT store raw PII in operational logs.

## Allowed stored/logged fields

Allowed audit fields:

- `timestampBucket` (rounded to 5-minute buckets)
- `requestId` (ephemeral request correlation ID)
- `verifierHash` (rotated salted SHA-256)
- `verdict` (`ALLOW` / `DENY` / `PROMPT`)
- `reasonCode` (from `DenyReasonCode` only)

Forbidden in operational logs:

- Raw subject DID
- Name
- Birthdate / age-date inputs
- Email
- Raw verifier DID

## Anti-correlation rules

- No stable correlators across relying parties: verifier identifiers MUST be salted hashes.
- Salt rotation SHOULD be periodic (e.g., monthly per deployment profile).
- Timestamps MUST be bucketed to 5-minute granularity.
- Cross-RP joins using stable IDs MUST NOT be possible from logs.

## Audience split for reason codes

For DENY reasons, `src/packages/policy-engine/src/deny-reason-codes.ts` is canonical.

- **User audience:** actionable but privacy-preserving explanation.
- **Verifier audience:** bucketed anti-oracle message only.
- **Audit audience:** full technical reason.

Anti-oracle guidance: verifier-facing text MUST NOT allow rule probing via detailed error differences.

## Retention defaults

- Bucketed operational decision logs: 30 days default TTL.
- Aggregated non-user-specific metrics: 90 days default TTL.
- Exported compliance audit bundles: policy-defined; SHOULD be immutable once exported.

## User controls

User MUST be able to:

- Export wallet-held credentials and local decision history.
- Delete locally stored credentials.
- Reset local state (including revocation/status caches and nonce caches).

## Verification steps

Automated checks are implemented in policy-engine tests:

- no raw PII in serialized audit record
- forbidden fields absent from schema
- timestamp bucket enforcement

Manual verification:

- `// TODO(manual-verify):` Confirm downstream log sinks preserve schema without adding raw request payloads.
