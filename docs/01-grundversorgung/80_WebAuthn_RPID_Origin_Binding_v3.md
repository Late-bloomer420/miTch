# 80 — WebAuthn RP-ID / Origin Binding v3

Stand: 2026-02-11

## Added hardening
Strong re-auth scaffold now also validates:
- `reAuthRpId` against `WEBAUTHN_RPID_ALLOWLIST`
- `reAuthOrigin` against `WEBAUTHN_ORIGIN_ALLOWLIST`

## Security effect
Prevents cross-origin / wrong-RP reuse of re-auth evidence in strict mode.

## Combined strict checks now include
- assertion allowlist
- challenge allowlist + one-time challenge replay protection
- issuance freshness window
- RP-ID and origin binding
