# 65 — KPI Deny Category Visibility

Stand: 2026-02-11

Added explicit KPI fields so critical deny categories are visible without parsing raw logs:

- `deny_credential_revoked_total`
- `deny_status_source_unavailable_total`
- `deny_jurisdiction_incompatible_total`
- `deny_status_source_unavailable_rate`

Why this matters:
- Faster operational detection of status-provider outages.
- Better separation of policy/compliance denials vs infrastructure failures.
- Cleaner pilot evidence for reliability and security posture.
