# 99 — WebAuthn Allowlist-Mode Drift Warning

Stand: 2026-02-11

Added explicit visibility and warning for an important migration-risk posture:
- KPI field: `webauthn_allowlist_mode_enabled`
- `kpi:check` warning when:
  - strong re-auth is enabled, but
  - WebAuthn verify mode remains `allowlist`

Purpose:
Prevent lingering in weaker compatibility mode after enabling stronger re-auth policy.
