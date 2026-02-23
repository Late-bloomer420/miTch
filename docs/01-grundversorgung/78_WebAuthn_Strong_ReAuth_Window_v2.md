# 78 — WebAuthn Strong Re-Auth Window v2

Stand: 2026-02-11

## Hardening added
Strict re-auth scaffold now checks additional evidence constraints:
- challenge binding (`WEBAUTHN_CHALLENGE_ALLOWLIST`)
- freshness window (`WEBAUTHN_MAX_AGE_SECONDS`)
- required metadata includes `reAuthIssuedAt`

## Deny behavior
If evidence is stale/missing/invalid:
- `DENY_REAUTH_PROOF_INVALID`

## Note
This remains a scaffold, but materially tighter than assertion-only allowlist checks.
Next step is full server-side WebAuthn assertion verification.
