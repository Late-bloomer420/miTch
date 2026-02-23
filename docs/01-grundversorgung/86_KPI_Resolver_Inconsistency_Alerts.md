# 86 — KPI Resolver Inconsistency Alerts

Stand: 2026-02-11

`kpi:check` now evaluates resolver inconsistency thresholds:
- `KPI_WARN_RESOLVER_INCONSISTENT_TOTAL` (default: 5)
- `KPI_CRIT_RESOLVER_INCONSISTENT_TOTAL` (default: 20)

Behavior:
- warning threshold exceeded => WARNING issue
- critical threshold exceeded => CRITICAL issue (non-zero hard fail)

This makes resolver-path instability visible in automated checks.
