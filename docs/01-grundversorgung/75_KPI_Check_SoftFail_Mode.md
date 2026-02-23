# 75 — KPI Check Soft-Fail Mode

Stand: 2026-02-11

`npm run kpi:check` now supports warning behavior control:

- `KPI_FAIL_ON_WARNING=1` → warning issues return non-zero exit code (1)
- default (`KPI_FAIL_ON_WARNING` unset) → warnings are reported but do not fail CI
- critical issues always fail (exit code 2)

Use this to keep CI strict on critical security degradation while avoiding noisy warning-only pipeline breaks during pilot tuning.
