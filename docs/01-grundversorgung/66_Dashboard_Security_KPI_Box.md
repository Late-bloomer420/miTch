# 66 — Dashboard Security KPI Box

Stand: 2026-02-11

Added a dedicated security KPI section to `/dashboard` showing:
- `deny_credential_revoked_total`
- `deny_status_source_unavailable_total`
- `deny_jurisdiction_incompatible_total`
- `deny_status_source_unavailable_rate`

Purpose: make critical deny-category signals visible at a glance without opening `/kpi` JSON.
