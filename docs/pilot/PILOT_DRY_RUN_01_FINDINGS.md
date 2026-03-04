# PILOT_DRY_RUN_01 Findings

Source: `docs/pilot/PILOT_DRY_RUN_01.md` action items (AI-01..AI-06).

## Findings list

1. **AI-01** — `did:web:localhost` over HTTP had no explicit production block.
2. **AI-02** — WebAuthn timeout mapping between `DENY_PRESENCE_REQUIRED` and `DENY_REAUTH_REQUIRED` was unclear.
3. **AI-03** — `DENY_POLICY_MISMATCH` scenario coverage was implicit and should be explicit.
4. **AI-04** — Audit export format/schema was not explicitly specified.
5. **AI-05** — Low-risk stale-cache revocation grace could return `ALLOW`; pilot safety posture required strict fail-closed profile.
6. **AI-06** — Legacy `resolveDID()` default path still allowed mock fallback.

## Resolution status

- AI-01: **Closed (P0)** — localhost did:web blocked by default; explicit opt-in dev flag added.
- AI-05: **Closed (P0)** — strict pilot guidance documented in runbook/capability docs; negotiation enforces revocation-online capability.
- AI-06: **Closed (P0)** — legacy default resolver now fail-closed (no mock fallback).
- AI-02: **Open (P1)** — requires product/security decision and user messaging policy alignment.
- AI-03: **Open (P2)** — documentation/test coverage tidy-up.
- AI-04: **Open (P1)** — full audit export schema spec remains to be finalized.
