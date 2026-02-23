# 77 — StatusList Reference Validation v3 (Light)

Stand: 2026-02-11

## Added hardening
For `proofBundle.credentialStatus` references:
- URL must be valid and secure (`https://` by default)
- HTTP allowed only when `ALLOW_INSECURE_STATUS_URL=1` (test-only)
- `statusListIndex` must be numeric

## Deny behavior
Invalid status references now map to:
- `DENY_CREDENTIAL_STATUS_INVALID`

## Why
Prevents unsafe/malformed status references from silently flowing into status checks.
Keeps fail-closed behavior explicit and auditable.
