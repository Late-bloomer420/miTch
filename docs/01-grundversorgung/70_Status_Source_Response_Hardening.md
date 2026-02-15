# 70 — Status Source Response Hardening

Stand: 2026-02-11

## Implemented
- HTTP credential-status fetch now sends `Accept: application/json`.
- Response `Content-Type` must include `application/json` (otherwise fail-closed).
- Response payload shape is now validated:
  - must include at least one of: `revokedCredentialIds` or `revokedIndexes`
  - if present, each must be an array
- Response size is capped by `CREDENTIAL_STATUS_MAX_BYTES` (header + actual body length checked).
- Malformed/oversized payloads are treated fail-closed (`credential_status_unavailable` path).

## Security benefit
Prevents silent acceptance when status providers return unexpected/invalid JSON structures.
