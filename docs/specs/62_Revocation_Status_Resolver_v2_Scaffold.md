# 62 — Revocation Status Resolver v2 (Scaffold)

Stand: 2026-02-11

## Implemented
- New credential status resolver module: `src/proof/credentialStatus.ts`
- Modes:
  - `env` (default): reads `REVOKED_CREDENTIAL_IDS`
  - `http`: fetches JSON payload from `CREDENTIAL_STATUS_URL`
- Timeout-based fail-closed behavior in http mode (`CREDENTIAL_STATUS_TIMEOUT_MS`).

## Expected HTTP payload
```json
{
  "revokedCredentialIds": ["cred-1", "cred-2"]
}
```

## Fail-closed mapping
- If status source is unavailable/misconfigured in strict contexts, verifier maps to deny-biased crypto status path.

## Next step
- Move from credential-id list to StatusList2021 index-based checks (URL + bitstring index).
