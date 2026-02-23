# 43 — Pilot Next Steps Plan (Start Now)

Stand: 2026-02-11

## Objective
Move from technical prototype to pilot-ready verification service with auditable evidence.

---

## Block A — Pilot Hardening Final (Week 1)

## A1) Real key source integration (replace env-only key map)
- Outcome: verifier resolves keys from a managed source (file/URL/provider adapter)
- Owner: Backend/Security
- Exit criteria:
  - key lookup errors map deterministically
  - missing/revoked/active paths tested

## A2) Revocation behavior policy (explicit)
- Outcome: documented + enforced behavior for status unavailable scenarios
- Owner: Security/Product
- Exit criteria:
  - high-risk predicates fail closed
  - behavior captured in config/docs/tests

## A3) Auth hardening baseline
- Outcome: token policy + rotation checklist + environment guidance
- Owner: Platform
- Exit criteria:
  - auth required in pilot profile
  - unauthorized path tested

---

## Block B — Pilot Evidence Pack (Week 1-2)

## B1) Reproducible verification scenarios
- ALLOW valid signed request
- DENY replay
- DENY hash mismatch
- DENY auth missing/invalid
- DENY revoked key

## B2) KPI export + audit integrity report
- `/metrics`, `/metrics.csv`, `/kpi`, `/audit/verify` snapshots
- include sample-size context

## B3) False-deny adjudication process
- weekly review of denied samples
- record outcome via `/adjudicate`
- trend report in KPI dashboard

---

## Block C — Pilot Execution (Week 2)

## C1) RP integration #1
- objective: first external relying party completes E2E flow
- KPI: time-to-first-success

## C2) Two-week measured run
- collect KPI baseline and trend
- identify top 3 failure/override causes

## C3) Go/No-Go review
- use `22_Pilot_Go_NoGo_Template.md`
- decision based on measured thresholds, not intuition

---

## Start Immediately (Today)
1. Implement key source adapter interface (A1 scaffold)
2. Add tests for revoked/missing key behavior in HTTP flow
3. Run one local evidence cycle and export KPI + audit verify output
