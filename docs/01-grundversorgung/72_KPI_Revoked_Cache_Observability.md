# 72 — KPI Revoked Cache Observability

Stand: 2026-02-11

Added KPI visibility for revoked-only cache behavior:
- `revoked_cache_hit_total`
- `revoked_cache_store_total`

Purpose:
- Detect unusual cache dependence patterns.
- Provide audit evidence that cache is active but bounded.
- Support investigation of status-provider instability.
