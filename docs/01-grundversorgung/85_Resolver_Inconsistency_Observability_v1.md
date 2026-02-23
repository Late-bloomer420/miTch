# 85 — Resolver Inconsistency Observability v1

Stand: 2026-02-11

Added resolver telemetry surfaced in KPI/dashboard:
- `resolver_queries_total`
- `resolver_quorum_failures_total`
- `resolver_inconsistent_responses_total`

Purpose:
- Detect resolver disagreement patterns early
- Make quorum failures visible in pilot evidence
- Support deny-biased operational response on resolver instability
