# 39 — Pilot KPI Dashboard Template

Stand: 2026-02-11  
Cadence: weekly (recommended)

---

## A) Reporting Metadata
- Week:
- Environment: dev / staging / pilot
- RP cohort:
- Sample size (#requests):
- Notes on incidents/changes:

---

## B) KPI Table (Core + Business)

| KPI | Definition (short) | Target | Week Value | Trend vs Prev | Status (G/Y/R) | Notes / Action |
|---|---|---:|---:|---|---|---|
| Replay/Context-Swap Block Rate | blocked attacks / attempts | 100% |  |  |  |  |
| Raw-PII Leakage Findings | findings in logs/receipts | 0 |  |  |  |  |
| Deny Mapping Coverage | coded denies / all denies | 100% |  |  |  |  |
| Latency p50 (ms) | verification latency | <=500 |  |  |  |  |
| Latency p95 (ms) | verification latency | <=1500 |  |  |  |  |
| Verification Success Rate | successes / valid attempts | >=99% |  |  |  |  |
| Cost per Verification | infra+ops / success | downtrend |  |  |  |  |
| False Deny Rate | legit denied / legit total | low threshold |  |  |  |  |
| Policy Override Rate | manual overrides / decisions | near 0 |  |  |  |  |
| RP Time-to-First-Success | integration start -> first ALLOW | downtrend |  |  |  |  |

---

## C) Drilldown (per RP)

### RP: <name>
- Requests:
- ALLOW:
- DENY:
- Top deny codes:
  -
  -
- p50/p95 latency:
- False deny review outcome:
- Actions next week:

(duplicate section for each RP)

---

## D) Risk & Decision Summary
- Top 3 risks observed this week:
  1.
  2.
  3.
- Decisions made:
- Escalations needed:

---

## E) Go/No-Go Pulse
- Current pulse: GO / GO-with-constraints / NO-GO
- Why:
- Preconditions for next phase:
