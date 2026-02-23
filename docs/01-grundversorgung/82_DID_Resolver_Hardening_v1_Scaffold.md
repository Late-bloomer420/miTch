# 82 — DID Resolver Hardening v1 (Scaffold)

Stand: 2026-02-11

## Goal
Prepare defenses against resolver-path manipulation (e.g., DNS/BGP/eclipse-style issues) without overloading current MVP scope.

## v1 Scaffold decisions
1. Add explicit roadmap item for multi-resolver quorum checks.
2. Require strict HTTPS-only resolver endpoints in production profile.
3. Add resolver timeout + retry budget policy (deny-biased on inconsistency).
4. Add result-consistency logging for future KPI tracking.

## Minimal acceptance for next implementation batch
- Config shape for resolver list + quorum threshold documented.
- Placeholder verifier hook defined (no silent trust in single resolver).
- Test plan includes mismatch scenario => deny.

## Why now
This is a high-leverage prep step from the external findings and keeps implementation batches small and auditable.
