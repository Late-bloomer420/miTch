# 58 — Revocation Baseline v1

Stand: 2026-02-11

## Implemented
- Key revocation deny path already active (`REVOKED_KEY_IDS`).
- Credential-level revocation deny path added (`REVOKED_CREDENTIAL_IDS`).
- Verifier denies revoked credential IDs using existing deny-biased crypto status mapping.

## Current behavior
- If `proofBundle.credentialId` is listed in `REVOKED_CREDENTIAL_IDS`, request is denied.
- Deny code currently maps to `DENY_CRYPTO_KEY_STATUS_INVALID` (status-invalid class).

## Why this matters
This closes an immediate gap from the external findings: revocation must exist before production, even if full StatusList2021 scale architecture is not yet implemented.

## Next step (v2)
1. Add StatusList2021-compatible resolver (URL + index).
2. Add cache + timeout policy with explicit fail-closed semantics.
3. Add dedicated deny code for credential revocation state if needed for clearer RP handling.
