# 67 — Strong Re-Auth Scaffold v1 (WebAuthn Hook)

Stand: 2026-02-11

## Implemented
- Added strict re-auth mode gate for proof-fatigue bypass.
- New deny code: `DENY_REAUTH_PROOF_INVALID`.
- In strict mode (`REQUIRE_STRONG_REAUTH=1`), simple `meta.reAuthRecent=true` is no longer sufficient.
- Expected metadata in strict mode:
  - `meta.reAuthMethod = webauthn`
  - `meta.reAuthAssertion` present and valid against configured allowlist scaffold.

## Security impact
- Removes blind trust in boolean re-auth flag under strict mode.
- Establishes migration path to real server-side WebAuthn assertion verification.
