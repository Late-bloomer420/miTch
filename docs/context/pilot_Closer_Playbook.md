# pilot_Closer_Playbook.md

Stand: 2026-02-12
Purpose: operational playbook to close the first issuer + RP pilot with measurable, auditable outcomes.

---

## 0) Mission
Close and survive the first pilot by proving 4 things:
1. Fast integration
2. Fail-closed security behavior
3. Compliance-evidence readiness
4. Clear commercial value (risk/cost/time)

---

## 1) Pilot closure criteria (must all be true)
- 1 issuer integrated for target use case
- 1 RP integrated end-to-end
- Time-to-first-success measured and acceptable
- False allow remains 0 in adversarial + real traffic samples
- Evidence pack complete (`/kpi`, `/metrics`, `/audit/verify`, adjudication samples)
- Legal/compliance narrative consistent with implemented behavior (no overclaiming)

---

## 2) Weekly operating cadence (repeat)

### Monday — Decide
- Review `105_Visual_Control_Panel.md`
- Keep NOW list max 3
- Re-score active items with `103_GTM_Security_Decision_Framework.md`
- Kill or defer anything without pilot impact this quarter

### Wednesday — Build + Prove
- Execute top hardening/integration item
- Run tests + KPI checks
- Collect one evidence snapshot
- Update blocker list with owner and deadline

### Friday — Close Loop
- RP/issuer feedback review (what blocked adoption this week?)
- Update risk/decision docs
- Confirm next week’s top 3 actions
- Prepare short pilot status note (technical + commercial)

---

## 3) Pilot workstreams (parallel)

### A) Integration speed
Owner: Engineering
- API quickstart should be copy/paste
- Integration target: <2 days for RP baseline
- Provide failure cookbook (deny codes -> operator action)

### B) Security assurance
Owner: Security
- Native/signed WebAuthn path clarity
- Revocation fail-closed behavior
- Resolver consistency/no-silent-allow guardrails
- Keep `false_allow_total = 0`

### C) Evidence and auditability
Owner: Security/Platform
- Export repeatable evidence bundle weekly
- Include denominator/sample sizes and interpretation notes
- Track false-deny adjudication trends

### D) Commercial + legal closure
Owner: Product/Legal
- Liability model draft in plain language
- Compliance mapping narrative (controls -> evidence)
- Buyer-facing one-pager: risk down / cost down / faster compliance flow

---

## 4) Pilot dashboard (minimum fields)
- RP integration stage: Not started / In progress / Live
- Issuer integration stage: Not started / In progress / Live
- Time-to-first-success (hours)
- `false_allow_total`
- top deny reasons (weekly)
- override rate
- adjudication pass/fail trend
- security profile score + caveat

---

## 5) Meeting templates

### 5.1 Internal 15-min standup
- What moved pilot probability this week?
- What is blocked by dependency (issuer/legal/ops)?
- Which item should be deferred now?

### 5.2 RP weekly sync
- Integration progress and blockers
- Top 3 denies and remediation path
- Evidence and audit questions
- Next concrete test milestone

### 5.3 Issuer weekly sync
- Credential/status/revocation integration state
- Trust and outage behavior expectations
- Pending legal/compliance alignment points

---

## 6) Risk triggers (automatic escalation)
Escalate within 24h if any occurs:
- false allow incident
- repeated unresolved deny spike in critical flow
- evidence integrity check failure
- security claims diverge from real config/runtime
- legal/compliance objection that invalidates pilot narrative

---

## 7) Anti-drift rules
- No new feature track without decision card
- No “security by claim” (must be measurable)
- No narrative drift toward identity empire framing
- No expansion before first issuer + RP pilot proof

---

## 8) First 14 days checklist
Day 1-2
- Confirm issuer + RP contacts, scope, and target flow
- Freeze NOW top 3 priorities

Day 3-5
- Complete RP integration baseline
- Validate deny-code handling and operator cookbook

Day 6-8
- Run adversarial scenarios + collect evidence
- Review legal/compliance narrative accuracy

Day 9-11
- Address top blockers from RP/issuer feedback
- Re-test and compare KPI deltas

Day 12-14
- Execute Go/No-Go evaluation (`22_Pilot_Go_NoGo_Template.md`)
- Decide: continue, constrain, or defer pilot

---

## 9) References
- `103_GTM_Security_Decision_Framework.md`
- `105_Visual_Control_Panel.md`
- `106_Document_Map_By_Purpose.md`
- `43_Pilot_Next_Steps_Plan.md`
- `22_Pilot_Go_NoGo_Template.md`
- `STATE.md`
