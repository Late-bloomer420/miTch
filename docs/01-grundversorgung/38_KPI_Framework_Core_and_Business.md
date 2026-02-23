# 38 — KPI Framework (Core + Business)

Stand: 2026-02-11

## Core Security/Privacy KPI
1. **Replay/Context-Swap Block Rate**
   - Definition: blocked replay/context-swap attempts / total detected attempts
   - Target: **100% blocked**

2. **Raw-PII Leakage Findings**
   - Definition: count of raw-PII findings in verifier logs/receipts
   - Target: **0**

3. **Deterministic Deny Mapping Coverage**
   - Definition: deny outcomes mapped to catalog codes / total deny outcomes
   - Target: **100% mapped**

4. **Latency (p50/p95)**
   - Definition: end-to-end verification latency percentiles
   - Target (pilot): p50 <= 500ms, p95 <= 1500ms

## Product/Business KPI (Non-Optional)
5. **Verification Success Rate**
   - Definition: successful verifications / total valid attempts
   - Target: >= 99% in controlled pilot

6. **Cost per Verification**
   - Definition: infra+ops cost / successful verifications
   - Target: downward trend over pilot iterations

7. **False Deny Rate**
   - Definition: legitimate requests denied / legitimate requests total
   - Target: as low as possible, explicit threshold per pilot

8. **Policy Override Rate**
   - Definition: manual overrides / total decisions
   - Target: near zero (high values signal policy/UX mismatch)

9. **RP Integration Time-to-First-Success**
   - Definition: time from integration start to first valid ALLOW+receipt
   - Target: reduce each cohort

---

## Measurement Notes
- Track KPI per RP and aggregated.
- Separate technical failures from policy-deny outcomes.
- Report weekly trend, not only point-in-time values.
- Always pair KPI with confidence/context notes (sample size, environment).
