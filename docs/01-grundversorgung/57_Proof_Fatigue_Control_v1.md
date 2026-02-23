# 57 — Proof Fatigue Control v1

Stand: 2026-02-11

## Objective
Reduce social-engineering success probability from repeated high-risk verification prompts.

## Implemented in v1
- New gate in verifier flow: proof-fatigue check (deny-biased).
- High-risk detection by:
  - purpose list (`HIGH_RISK_PURPOSES`)
  - sensitive claim names (`SENSITIVE_CLAIMS`)
- Thresholds:
  - `PROOF_FATIGUE_WINDOW_SECONDS` (default 3600)
  - `PROOF_FATIGUE_MAX_HIGH_RISK_PROMPTS` (default 5)
- Deny code on threshold breach:
  - `DENY_REAUTH_REQUIRED`
- Bypass condition (explicit signal from caller):
  - `meta.reAuthRecent = true`

## Security posture
- Fail-closed: repeated high-risk prompts are denied unless recent re-auth is indicated.
- Conservative by design: this is a baseline control, not full phishing resistance.

## Next hardening
1. Bind `reAuthRecent` to cryptographic/user-presence proof (e.g., WebAuthn assertion), not plain boolean.
2. Add independent telemetry counters for fatigue-triggered denials.
3. Add RP-facing guidance for handling `DENY_REAUTH_REQUIRED`.
