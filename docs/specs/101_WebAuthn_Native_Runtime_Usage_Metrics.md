# 101 — WebAuthn Native Runtime Usage Metrics

Stand: 2026-02-12

Added runtime (event) telemetry for native WebAuthn verification path:
- `webauthn_native_attempt_total`
- `webauthn_native_success_total`
- `webauthn_native_deny_total`
- `webauthn_native_success_rate`

Scope note:
- These metrics reflect actual verification attempts in native mode, not only config posture.
- This improves pilot visibility for drift, misuse, and adapter stability.
