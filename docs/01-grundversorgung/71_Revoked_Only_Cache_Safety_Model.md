# 71 — Revoked-Only Cache Safety Model

Stand: 2026-02-11

## Design decision
Local in-memory cache stores **revoked=true signals only**.

## Security rationale
- Never caches allow/not-revoked outcomes.
- Prevents long-lived fail-open behavior from stale positive status.
- Supports fail-closed continuity when status source briefly degrades.

## Controls
- TTL: `CREDENTIAL_STATUS_REVOKED_CACHE_TTL_MS` (default 10s)
- Size bound: `CREDENTIAL_STATUS_REVOKED_CACHE_MAX_ENTRIES` (default 1000)
- Scope: process-local RAM only (not persisted, not exported)

## Expected behavior
- Same credential/index recently marked revoked keeps denying during short provider outage.
- Different credential/index does not inherit allow from cache and still fails closed if source unavailable.
