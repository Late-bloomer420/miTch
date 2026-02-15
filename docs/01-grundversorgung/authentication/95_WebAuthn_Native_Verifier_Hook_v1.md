# 95 — WebAuthn Native Verifier Hook v1

Stand: 2026-02-11

## Added
Introduced a dedicated verifier module (`src/api/webauthnVerifier.ts`) and support for:
- `WEBAUTHN_VERIFY_MODE=allowlist|signed|native`

## Native mode behavior
- Defaults to deny unless an explicit trusted adapter signal is present (`WEBAUTHN_NATIVE_ADAPTER_OK=1`).
- This is a transition hook for plugging in real authenticator verification later.

## Why this helps
- Separates verification implementation behind a stable interface.
- Keeps current secure defaults (deny-biased) while enabling future full WebAuthn verifier integration.
