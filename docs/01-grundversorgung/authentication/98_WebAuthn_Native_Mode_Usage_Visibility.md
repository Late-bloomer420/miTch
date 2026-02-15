# 98 — WebAuthn Native Mode Usage Visibility

Stand: 2026-02-11

Added KPI visibility for native WebAuthn hook usage posture:
- `webauthn_native_mode_enabled`

Also surfaced in dashboard and `kpi:check` output.

Additional check rule:
- Warning if native mode is enabled while strong re-auth is not enabled.
