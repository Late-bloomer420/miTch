# 89 — KPI Alerts for Deny Resolver Quorum Failed

Stand: 2026-02-11

Added `kpi:check` thresholds for deny outcomes tied to resolver no-quorum events:
- `KPI_WARN_DENY_RESOLVER_QUORUM_FAILED_TOTAL` (default 2)
- `KPI_CRIT_DENY_RESOLVER_QUORUM_FAILED_TOTAL` (default 10)

This complements resolver telemetry alerts with direct decision-impact alerting.
