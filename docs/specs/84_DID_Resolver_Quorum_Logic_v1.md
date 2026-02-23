# 84 — DID/Key Resolver Quorum Logic v1

Stand: 2026-02-11

## Implemented
- HTTP key source supports multi-endpoint quorum retrieval.
- Config supports:
  - `KEY_SOURCE_URLS` (comma-separated)
  - `KEY_SOURCE_QUORUM`
  - `KEY_SOURCE_TIMEOUT_MS`
- If no key value reaches quorum, resolver returns no key (deny-biased downstream).

## Security value
Reduces single-resolver trust and helps mitigate path manipulation / inconsistent resolver responses.

## Test coverage
- Added test: `httpKeySourceQuorum.ts`
  - 2/3 agreement returns quorum winner
  - 3/3 required with disagreement returns null
