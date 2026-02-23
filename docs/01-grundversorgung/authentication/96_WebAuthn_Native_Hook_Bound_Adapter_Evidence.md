# 96 — WebAuthn Native Hook: Bound Adapter Evidence

Stand: 2026-02-11

## Hardening update
Native WebAuthn hook mode no longer accepts a generic "adapter OK" flag.
It now requires cryptographically bound adapter evidence:
- `WEBAUTHN_VERIFY_MODE=native`
- assertion verified via HMAC over `native|challenge|rpId|origin|issuedAt`
- key: `WEBAUTHN_NATIVE_ADAPTER_SECRET`

## Security effect
Prevents broad bypass via global flag and binds acceptance to request-specific evidence.
