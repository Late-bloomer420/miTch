# 63 — Dedicated Deny Code for Revoked Credential

Stand: 2026-02-11

## Change
Added dedicated deny code: `DENY_CREDENTIAL_REVOKED`.

## Why
Separates credential-level revocation from key-status errors for clearer RP handling and better KPI diagnostics.

## Effect
- `revoked_credential` path now maps to `DENY_CREDENTIAL_REVOKED`.
- Key-level issues remain under `DENY_CRYPTO_KEY_STATUS_INVALID`.
