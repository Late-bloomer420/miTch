# 93 — PQ Readiness: Crypto Agility v1

Stand: 2026-02-11

## Implemented now
- Signature algorithm allowlist is now runtime-configurable via:
  - `ALLOWED_ALGS` (default: `EdDSA`)
- Unsupported algorithms continue to deny (`DENY_CRYPTO_UNSUPPORTED_ALG`).
- KPI now exposes `crypto_allowed_algs_count` for visibility.

## Why this matters
This does not make miTch post-quantum secure yet, but it creates a controlled migration lever for future hybrid/PQ rollout.
