# 83 — DID Resolver Config Profile v1

Stand: 2026-02-11

## Purpose
Define a minimal configuration shape for future DID resolver hardening (quorum + consistency checks).

## Proposed env variables
- `DID_RESOLVER_URLS=https://resolver1.example,https://resolver2.example,https://resolver3.example`
- `DID_RESOLVER_QUORUM=2`
- `DID_RESOLVER_TIMEOUT_MS=1200`
- `DID_RESOLVER_ALLOW_INSECURE=0` (test-only override)

## Planned behavior (next implementation step)
1. Query multiple resolvers in parallel.
2. Require quorum-consistent document result.
3. Deny on mismatch/timeout beyond quorum.
4. Emit consistency event for observability.
