# 87 — KPI Resolver Quorum Failure Alerts

Stand: 2026-02-11

`kpi:check` now evaluates quorum-failure drift thresholds:
- `KPI_WARN_RESOLVER_QUORUM_FAILURES_TOTAL` (default: 5)
- `KPI_CRIT_RESOLVER_QUORUM_FAILURES_TOTAL` (default: 20)

This complements inconsistency alerts and improves early detection of resolver instability that can reduce successful verification continuity.
