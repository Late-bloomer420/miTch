# 103 — GTM + Security Decision Framework (Lean)

## Why this exists
This framework turns strategy into repeatable decisions.
Use it for **every** feature, roadmap item, and architecture change.

Goal: ship what improves adoption, compliance confidence, and security posture — not just technical elegance.

---

## Usage rule (non-negotiable)
Before work starts, fill this in.
If sections are unclear, default to **PILOT** or **DEFER** (never assume GO).

---

## Decision Card (copy/paste)

### 0) Item
- **Name:**
- **Owner:**
- **Date:**
- **Status:** Draft / GO / PILOT / DEFER

### 1) Buyer value (RP/CFO language)
- **Pain solved (money, risk, time):**
- **Expected measurable impact:**
  - Conversion impact:
  - Compliance effort impact:
  - Liability/risk impact:
- **Confidence:** Low / Medium / High

### 2) Adoption friction (integration reality)
- **Integration effort:** <2 days / 2–5 days / >5 days
- **New protocol/process required for RP?:** Yes / No
- **Operational burden added?:** Low / Medium / High
- **Dependencies:** (issuer/legal/infra/vendor)

### 3) Assurance profile (security truth)
- **Assurance tier:** Software mode / Hardware-backed mode / Mixed
- **Main threats reduced:**
- **Residual risks still open:**
- **Acceptable for which customer tier?:**

### 4) Compliance & evidence
- **Regulatory/control mapping:**
- **Evidence generated (logs, receipts, KPIs):**
- **Audit-readiness level:** Low / Medium / High

### 5) Pilot fit (this quarter)
- **Helps win 1 issuer + 1 RP pilot now?:** Yes / No / Partial
- **Time-to-first-value:**
- **Prerequisites for pilot:**

### 6) Decision
- **Verdict:** GO / PILOT / DEFER
- **Reason (max 5 lines):**
- **Next 3 steps:**
  1.
  2.
  3.

### 7) Kill criteria (anti-drift)
If any is true, stop or re-scope:
- No measurable buyer value
- Integration effort exceeds target with no clear ROI
- Compliance evidence cannot be demonstrated
- Security improvement is theoretical only (no observable control/KPI)

---

## Weekly cadence (20–30 min)
- Review all cards marked GO/PILOT.
- Remove or defer items without measurable progress.
- Promote only items that improve pilot probability.

---

## Scoring shortcut (optional)
Score each 1–5, then sum:
- Buyer value
- Adoption ease
- Security impact
- Compliance clarity
- Pilot immediacy

**Interpretation:**
- 21–25: GO now
- 15–20: PILOT with constraints
- <=14: DEFER
