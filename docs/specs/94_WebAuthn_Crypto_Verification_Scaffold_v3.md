# 94 — WebAuthn Crypto Verification Scaffold v3

Stand: 2026-02-11

## Added
Strong re-auth mode now supports a cryptographic assertion verification scaffold:
- `WEBAUTHN_VERIFY_MODE=signed`
- verifies assertion as HMAC-SHA256 over:
  - `challenge|rpId|origin|issuedAt`
- key: `WEBAUTHN_ASSERTION_HMAC_SECRET`

## Existing controls still apply
- challenge one-time-use replay protection
- challenge allowlist
- rpId/origin allowlists
- freshness window (`WEBAUTHN_MAX_AGE_SECONDS`)

## Note
This is still not full WebAuthn authenticator verification, but it replaces plain assertion allowlisting with signed evidence checks.
