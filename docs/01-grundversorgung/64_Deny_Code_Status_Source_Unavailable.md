# 64 — Dedicated Deny Code for Status Source Unavailability

Stand: 2026-02-11

## Change
Added `DENY_STATUS_SOURCE_UNAVAILABLE`.

## Why it improves security
- Makes status-provider outages explicit and auditable.
- Prevents ambiguous mapping to generic crypto-failure classes.
- Supports stricter operator alerting and KPI tracking for dependency health.

## Current behavior
- Key-status unavailable and credential-status unavailable now map to this dedicated deny code.
