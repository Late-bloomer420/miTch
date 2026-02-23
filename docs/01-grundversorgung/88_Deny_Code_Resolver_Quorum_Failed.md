# 88 — Dedicated Deny Code: Resolver Quorum Failed

Stand: 2026-02-11

## Added
- New deny code: `DENY_RESOLVER_QUORUM_FAILED`

## Mapping
- Triggered when HTTP multi-resolver key lookup returns inconsistent/no-quorum outcome.
- Distinct from generic missing-key and status-unavailable paths.

## Why
Improves incident diagnosis by separating resolver disagreement from key absence.
