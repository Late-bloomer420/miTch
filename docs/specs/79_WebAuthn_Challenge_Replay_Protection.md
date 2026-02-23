# 79 — WebAuthn Challenge Replay Protection

Stand: 2026-02-11

## Added
- One-time-use challenge enforcement in strong re-auth mode.
- Reused `reAuthChallenge` within validity window is denied.

## Behavior
- First valid assertion/challenge pair can pass.
- Replay of same challenge maps to `DENY_REAUTH_PROOF_INVALID`.

## Security value
Reduces risk of replaying captured re-auth evidence to bypass proof-fatigue controls.
