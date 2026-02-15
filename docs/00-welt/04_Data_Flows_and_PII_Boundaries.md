# Data Flows & PII Boundaries (Critical)

## Goal
**PII must not leave the issuer/state domain as raw attributes.** Requesters should only receive minimal proofs.

## Boundary rule
- Raw identity attributes (name, passport number, DOB, address, biometrics) remain inside:
  - state registries / issuer systems, or
  - the user’s own device storage under user control.
- Outside these domains, only **derived proofs** and **minimal claims** may flow.

## Recommended patterns
### 1) Predicate proofs (preferred)
- Prove: `age >= 18`, `residency == AT`, `license_valid == true`
- Do NOT reveal: date of birth, full address, license number

### 2) Selective disclosure credentials
- If RP truly needs a subset of attributes, disclose only those attributes explicitly required.
- Always bind to purpose + audience.

### 3) Request-context binding
- Every proof must be bound to:
  - request nonce / request hash
  - intended audience (RP identifier)
  - expiry window

## Metadata leak hardening
Even if content is minimized, **metadata leaks** can deanonymize.
Mitigations:
- Normalize and minimize logs (no full IP, no stable user identifiers).
- Avoid stable correlation handles (no persistent user IDs across RPs).
- Use short-lived session identifiers; rotate keys for different audiences.
- Rate limit per requester/service identity, not per user identity.

## Fail-closed requirements
- Missing purpose, missing claims spec, or unsupported predicate => DENY.
- RP asks for unnecessary attributes => DENY or require user explicit override (and log it locally).
