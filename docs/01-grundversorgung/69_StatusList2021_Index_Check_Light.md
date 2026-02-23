# 69 — StatusList2021 Index Check (Light)

Stand: 2026-02-11

## Implemented in this batch
- Credential revocation check now supports index-based deny signals.
- Env mode:
  - `REVOKED_STATUS_LIST_INDEXES=42,99`
- HTTP mode payload may include:
  - `revokedIndexes: [42, 99]`
  - in addition to `revokedCredentialIds`.

## Notes
- This is a light scaffold, not full StatusList2021 bitstring decoding yet.
- It provides an incremental, standards-aligned transition path with minimal complexity.
