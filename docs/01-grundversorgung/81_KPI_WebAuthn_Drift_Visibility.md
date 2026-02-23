# 81 — KPI WebAuthn Drift Visibility

Stand: 2026-02-11

Added explicit KPI signal:
- `deny_reauth_proof_invalid_total`

Also surfaced in dashboard security KPI section.

Purpose:
- Detect re-auth verification drift/misconfiguration early
- Separate WebAuthn evidence failures from other deny classes
