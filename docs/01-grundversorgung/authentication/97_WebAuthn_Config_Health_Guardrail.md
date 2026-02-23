# 97 — WebAuthn Config Health Guardrail

Stand: 2026-02-11

Added KPI/config health visibility for strong re-auth:
- `reauth_strong_enabled`
- `webauthn_verify_mode_code` (0 allowlist, 1 signed, 2 native)
- `webauthn_secret_config_valid` (1/0)

`kpi:check` now raises CRITICAL when strong re-auth is enabled but WebAuthn secret configuration is invalid for signed/native modes.
