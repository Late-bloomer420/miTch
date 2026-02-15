# 34 — Use Case Prioritization Matrix

Stand: 2026-02-11

Scoring: 1 (low) to 5 (high)  
Weighted score = Pain(30%) + Willingness(25%) + Integration Ease(20%) + Regulatory Simplicity(15%) + Differentiation(10%)

| Use case | Pain | Willingness | Integration Ease | Regulatory Simplicity | Differentiation | Weighted Score |
|---|---:|---:|---:|---:|---:|---:|
| Age verification (18+) | 5 | 4 | 4 | 4 | 4 | **4.35** |
| Residency/eligibility | 4 | 4 | 3 | 3 | 4 | **3.65** |
| Professional license validity | 4 | 5 | 2 | 2 | 4 | **3.55** |
| High-assurance onboarding (broad KYC-like) | 5 | 5 | 1 | 1 | 3 | **3.20** |

## Recommendation
Start with **Age verification (18+)** as first business case.
Second expansion path: residency predicate once issuer/status path stabilizes.

---

## Assumptions
- miTch remains mediator/proof layer, not identity data custodian
- authoritative data originates from issuer/state domain
- requesters receive minimal proof only

---

## Re-evaluation triggers
Re-score if any of the following changes:
- new issuer integration becomes available
- a design partner commits to paid pilot
- regulatory requirement changes in target market
- measured integration effort deviates >30% from plan
