# 45 — Adjudication Workflow (B3)

## Goal
Classify denied/flagged cases to measure true false-deny rate and improve policy quality.

## Fast path (CLI)
```powershell
cd C:\Users\Admin\Documents\miTch
npm run adjudicate -- <requestId> <legit|false_deny|false_allow>
```

Example:
```powershell
npm run adjudicate -- req-123 false_deny
```

## Alternative (HTTP)
Use authenticated endpoint:
- `POST /adjudicate`

## Weekly process
1. Sample denied decisions from recent logs.
2. Mark each sampled case with adjudication outcome.
3. Re-check `/kpi` (`false_deny_rate`) trend.
4. Create action items for top deny causes.

## Why this matters
Without adjudication data, false-deny is guesswork.
With adjudication, KPI 7 becomes evidence-based.
