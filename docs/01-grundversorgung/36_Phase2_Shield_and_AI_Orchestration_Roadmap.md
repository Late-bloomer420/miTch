# 36 — Phase 2 Roadmap: Shield + AI Orchestration

Stand: 2026-02-11

## Guiding principle
Phase 2 starts only after Core MVP success criteria are met.

---

## Track A — Shield (Web Runtime Privacy)

### A1: Visibility Baseline
- Show data-request events by site/service
- Classify request sensitivity (low/medium/high)
- User event timeline (local-first)

### A2: Policy Controls
- Allow / deny / notify rules by category
- Fallback behavior for non-blockable requests (notify + warn)
- Tamper-evident local activity log

### A3: Metadata Controls
- Minimize persistent identifiers
- Session scoping and rotation
- Correlation resistance checks

---

## Track B — AI Orchestration Privacy Layer

### B1: Outbound Content Guard
- PII/secret detector + redaction policies
- Purpose-bound outbound payload shaping
- Model-specific policy contracts

### B2: Semantic Minimization
- Transform user prompt/content to least-disclosure form
- Preserve utility while reducing identifiability
- Decision receipts for transformed outputs

### B3: Enterprise/Private Profiles
- Policy bundles for business and personal contexts
- Separate trust domains and retention settings
- Auditable compliance mode for regulated teams

---

## Entry criteria for Phase 2
- Core pilot completed (Go decision)
- Stable API contract and deny-code behavior
- Operations baseline in place (incident + security gates)

## Exit criteria for Phase 2
- Shield MVP with actionable user controls
- AI mediation MVP with policy-enforced outbound sanitization
- Measured reduction in sensitive outbound leakage
