# 40 — KPI Definitions & Data Sources

Stand: 2026-02-11

## Purpose
Make KPI reporting reproducible by defining exact formulas, source signals, and ownership.

---

## KPI Catalog

## 1) Replay/Context-Swap Block Rate
- Formula: `blocked_replay_attempts / total_replay_attempts`
- Source: verifier decision logs (`DENY_BINDING_NONCE_REPLAY`, `DENY_BINDING_AUDIENCE_MISMATCH`, `DENY_BINDING_HASH_MISMATCH`)
- Owner: Security Engineering
- Frequency: weekly + incident-driven

## 2) Raw-PII Leakage Findings
- Formula: count of confirmed raw-PII log/receipt findings
- Source: log scanning pipeline + manual security review
- Owner: Privacy Engineering
- Frequency: weekly

## 3) Deny Mapping Coverage
- Formula: `denies_with_catalog_code / total_denies`
- Source: decision stream audit
- Owner: Backend
- Frequency: weekly

## 4) Latency p50 / p95
- Formula: percentile over end-to-end verify duration
- Source: request start/end timestamps in verifier telemetry
- Owner: Platform
- Frequency: daily dashboard, weekly report

## 5) Verification Success Rate
- Formula: `ALLOW decisions / valid verification attempts`
- Source: decision receipts and request validation logs
- Owner: Product + Platform
- Frequency: weekly

## 6) Cost per Verification
- Formula: `(infra + ops cost) / successful verifications`
- Source: cloud billing + ops hours + throughput counters
- Owner: Product Ops / Finance
- Frequency: weekly/monthly trend

## 7) False Deny Rate
- Formula: `legit requests denied / legit requests`
- Source: sampled denied cases + adjudication workflow
- Owner: Trust & Safety / Product
- Frequency: weekly

## 8) Policy Override Rate
- Formula: `manual overrides / total decisions`
- Source: override audit records
- Owner: Policy Owner
- Frequency: weekly

## 9) RP Time-to-First-Success
- Formula: `timestamp(first ALLOW+receipt) - integration start`
- Source: onboarding tracker + first success event
- Owner: Integrations / DevRel
- Frequency: per RP cohort

---

## Data Quality Rules
- All KPI events need stable event schema version.
- Separate technical errors from policy denials.
- Missing telemetry => metric marked invalid (not silently estimated).
- Keep privacy constraints: no raw PII in KPI datasets.

---

## Minimal Event Fields (recommended)
- `eventType` (request_received, decision_made, override_applied)
- `requestId`
- `rpId`
- `decision`
- `decisionCode`
- `startedAt`, `endedAt`
- `receiptRef`
- `schemaVersion`
