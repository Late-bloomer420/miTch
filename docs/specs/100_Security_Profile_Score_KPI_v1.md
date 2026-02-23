# 100 — Security Profile Score KPI v1

Stand: 2026-02-11

Added `security_profile_score` (0-100) to `/kpi` and dashboard.

## Purpose
Provide a compact posture signal for operational checks and go/no-go snapshots.

## Current scoring principles (deny-biased)
Penalizes score for:
- any `false_allow_total`
- weak WebAuthn posture (no strong mode / allowlist mode / invalid secret config)
- resolver no-quorum deny pressure
- status-source and resolver inconsistency signals

## `kpi:check` integration
- Warning when score < 80
- Critical when score < 60
