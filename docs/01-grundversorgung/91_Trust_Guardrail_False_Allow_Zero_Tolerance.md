# 91 — Trust Guardrail: False-Allow Zero Tolerance

Stand: 2026-02-11

You are right: even a single false-allow can severely damage trust.

## Guardrail added
- KPI now exposes `false_allow_total`.
- `kpi:check` treats `false_allow_total > 0` as **CRITICAL**.

## Operational implication
- Any confirmed false-allow must trigger immediate incident workflow.
- CI/ops checks will no longer report healthy status while false-allow count is non-zero.
